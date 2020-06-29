#!/usr/bin/env python

from qumulo.rest_client import RestClient
import os
import pwd
import sys
import ssl
import heapq
from argparse import ArgumentParser
from multiprocessing import Pool

class SampleTreeNode:
    def __init__(self, name, parent=None):
        self.parent = parent
        self.samples = 0
        self.name = name
        self.sum_samples = 0
        self.children = {}

    def insert(self, name, samples):
        self.insert_internal(name.split("/"), samples)

    def insert_internal(self, components, samples):
        if not components:
            self.samples += samples
        else:
            self.children.setdefault(components[0], SampleTreeNode(components[0], self))
            self.children[components[0]].insert_internal(components[1:], samples)
        self.sum_samples += samples

    def leaves(self):
        if not self.children:
            yield self
        for child in self.children.values():
            for result in child.leaves():
                yield result

    def merge_up(self):
        if not self.parent:
            return self
        self.parent.samples += self.samples
        del self.parent.children[self.name]
        return self.parent

    def prune_until(self, max_leaves=10, min_samples=5):
        leaves = []
        for leaf in self.leaves():
            leaves.append((leaf.samples, leaf))

        heapq.heapify(leaves)

        while leaves[0][1].parent:
            lowest = heapq.heappop(leaves)
            if lowest[0] > min_samples and len(leaves) < max_leaves:
                break
            new_node = lowest[1].merge_up()
            if len(new_node.children) == 0:
                heapq.heappush(leaves, (new_node.samples, new_node))

    def __str__(self, indent, format_samples, is_last=True):
        result = indent + (is_last and "\\---" or "+---") + self.name + ""
        if self.samples:
            result += "(%s)" % (format_samples(self.sum_samples),)

        next_indent = indent + (is_last and "    " or "|   ")
        sorted_children = sorted(self.children.values(),
                                 lambda x, y: cmp(x.name, y.name))
        for child in sorted_children[:-1]:
            result += "\n" + child.__str__(
                next_indent, format_samples, False)
        if sorted_children:
            result += "\n" + sorted_children[-1].__str__(
                next_indent, format_samples, True)

        return result

def pretty_print_capacity(x):
    start = (1024 ** k for k in (6, 5, 4, 3, 2, 1, 0))
    units = ("E", "P", "T", "G", "M", "K", "b")
    for l, u in zip(start, units):
        if x >= l: return "%0.02f%s" % (x / float(l), u)
    return 0

def get_samples_worker(x):
    credentials, path, n = x
    client = RestClient(credentials["cluster"], credentials["port"])
    client.login(credentials["user"], credentials["password"])
    return client.fs.get_file_samples(path=path, count=n, by_value="capacity")

class memoize:
  def __init__(self, function):
    self.function = function
    self.memoized = {}
  def __call__(self, *args):
    try:
      return self.memoized[args]
    except KeyError:
      self.memoized[args] = self.function(*args)
      return self.memoized[args]

def sid_to_username(client, idents):
    """Returns a username for a Active Directory SID"""
    for el in idents:
        if el['id_type'] == 'SMB_SID':
            smb_user = el['id_value']
            try:
                entry = client.ad.sid_to_ad_account(smb_user)
                # We're only interested in returning a result if there is matching user class
                if "user" in entry['classes']:
                    user_id = client.ad.sid_to_ad_account(smb_user)['name']
                    return "AD_USER:%s" % (user_id)
                else:
                    next
            except:
                next
    return None

@memoize
def enumerate_owner(client, path):
    owner = client.fs.get_file_attr(path)["owner"]
    owner_details = client.fs.get_file_attr(path)["owner_details"]
    owner_type = owner_details['id_type']
    owner_id = owner_details['id_value']
    idents = client.auth.auth_id_to_all_related_identities(owner)
    user_id = sid_to_username(client, idents)
    if user_id:
        return user_id
    for el in idents:
        ident = el
        if el['id_type'] == 'LOCAL_USER':
            return "%s:%s" % (el['id_type'], el['id_value'])
    for el in idents:
        if el['id_type'] == 'NFS_UID':
            return "%s:%s" % (el['id_type'], owner_id)

    return "%s:%s" % (owner_type, owner_id)

seen = {}
def get_file_attrs(x):
    credentials, paths = x
    client = RestClient(credentials["cluster"], credentials["port"])
    client.login(credentials["user"], credentials["password"])
    result = []
    for path in paths:
        if seen.has_key(path):
            result += [seen[path]]
            continue
        str_owner = enumerate_owner(client, path)
        seen[path] = str_owner
        result.append(str_owner)
    return result

def get_samples(pool, credentials, args):
    return sum(pool.map(
        get_samples_worker,
        ([(credentials, args.path, args.samples / args.concurrency)] * args.concurrency)),
                  [])

def get_owner_vec(pool, credentials, samples, args):
    file_ids = [s["id"] for s in samples]
    sublists = [(credentials, file_ids[i:i+100]) for i in xrange(0, args.samples, 100)]
    owner_id_sublists = pool.map(get_file_attrs, sublists)
    return sum(owner_id_sublists, [])

def main(args):
    credentials = {"user" : args.user,
                   "password" : args.password,
                   "cluster" : args.cluster,
                   "port" : args.port}

    if args.allow_self_signed_server:
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context

    # Qumulo API login
    client = RestClient(args.cluster, args.port)
    client.login(args.user, args.password)

    total_capacity_used = int(
        client.fs.read_dir_aggregates(args.path)['total_capacity'])

    pool = Pool(args.concurrency)

    # First build a vector of all samples...
    samples = get_samples(pool, credentials, args)

    # Then get a corresponding vector of owner strings
    owner_vec = get_owner_vec(pool, credentials, samples, args)

    owners = {}
    directories = {}

    # Create a mapping of user to tree...
    for s, owner in zip(samples, owner_vec):
        owners.setdefault(owner, SampleTreeNode(""))
        owners[owner].insert(s["name"], 1)

    def format_capacity(samples):
        mean = float(samples) / args.samples
        stddev = (((1 - mean) ** 2 * samples +
                   (mean ** 2) * (args.samples - samples)) / args.samples) ** (1/2.)
        confidence =  1.96 * stddev / (args.samples ** (1/2.))

        bytes_per_terabyte = 1000. ** 4
        if args.dollars_per_terabyte != None:
            to_dollars = lambda(adjust) : ((mean + adjust) * total_capacity_used /
                                           bytes_per_terabyte *
                                           args.dollars_per_terabyte)
            if args.confidence_interval:
                return "[$%0.02f-$%0.02f]/month" % (to_dollars(-confidence),
                                                    to_dollars(confidence))
            else:
                return "$%0.02f/month" % (to_dollars(0),)
        else:
            if args.confidence_interval:
                return "[%s-%s]" % (
                    pretty_print_capacity((mean - confidence) * total_capacity_used),
                    pretty_print_capacity((mean + confidence) * total_capacity_used))
            else:
                return "%s" % pretty_print_capacity((mean) * total_capacity_used)

    print "Total: %s" % (format_capacity(args.samples))
    sorted_owners = sorted(owners.items(),
                           lambda x, y: cmp(y[1].sum_samples, x[1].sum_samples))
    # For each owner, print total used, then refine the tree and dump it.
    for name, tree in sorted_owners:
        print "Owner %s (~%0.1f%%/%s)" % (
            name, tree.sum_samples / float(args.samples) * 100,
            format_capacity(tree.sum_samples))
        tree.prune_until(max_leaves=args.max_leaves,
                         min_samples=args.min_samples)

        print tree.__str__("    ", lambda x: format_capacity(x))

def process_command_line(args):
    parser = ArgumentParser()
    parser.add_argument("-U", "--user", default="admin",
            help="The user to connect as (default: %(default)s)")

    parser.add_argument("-P", "--password", default="admin",
        help="The password to connect with (default: %(default)s)")

    parser.add_argument("-C", "--cluster", default="qumulo",
        help="The hostname of the cluster to connect to (default: %(default)s)")

    parser.add_argument("-p", "--port", type=int, default=8000,
        help="The port to connect to (default: %(default)s)")

    parser.add_argument("-s", "--samples", type=int, default=2000,
        help="The number of samples to take (default: %(default)s)")

    parser.add_argument("-c", "--concurrency", type=int, default=10,
        help="The number of threads to query with (default: %(default)s)")

    parser.add_argument("-m", "--min-samples", type=int, default=5,
        help='''The minimum number of samples to show at a leaf in output
                (default: %(default)s)''')

    parser.add_argument("-x", "--max-leaves", type=int, default=30,
        help='''The maximum number of leaves to show per user
                (default: %(default)s)''')

    parser.add_argument(
        "-D", "--dollars-per-terabyte", type=float,
        help="Show capacity in dollars. Set conversion factor in $/TB/month")

    parser.add_argument("-i", "--confidence-interval", action="store_true",
        help="Show 95%% confidence intervals")

    parser.add_argument("-A", "--allow-self-signed-server", action="store_true",
        help="Silently connect to self-signed servers")

    parser.add_argument("path", help="Filesystem path to sample")

    return parser.parse_args(args)

if __name__ == '__main__':
    main(process_command_line(sys.argv[1:]))
