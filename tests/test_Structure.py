import unittest
from gdb_plus import *
import warnings
import timeout_decorator

gdbinit_native = """
set pagination off
"""

gdbinit_gef = """
source ~/.gdbinit-gef.py
"""

gdbinit_pwndbg = """
source /home/root/pwndbg/gdbinit.py
"""

QUICK = 10
MEDIUM = 30
LONG = 60

#@unittest.skip
class Debugger_structures(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)
        
    def tearDown(self):
        # import threading

        # # Print all running threads
        # for thread in threading.enumerate():
        #     print(f"Thread Name: {thread.name}, Thread ID: {thread.ident}, Daemon: {thread.daemon}")
        pass

    # Based on CCIT2025 rev 2
    # Testing Structure from text, from dict, access methods
    # @unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_writeup_structure(self):
        print("\ntest_writeup_structure: ", end="")

        CALL_SRAND = 0x18b1
        TREE_TO_STRING = 0x1611
        END_CORRUPT_TREE = 0x1b8c
        SHOW_SECRET = 0x1b16

        bin_tree_header = """
        typedef struct bin_tree {
            int             value;   // node value (e.g. a character or integer)
            int             pad_1;
            struct bin_tree *child1;    // first child pointer
            int             weight1;      // tag or weight for child1
            int             pad_2;
            struct bin_tree *child2;    // second child pointer
            int             weight2;      // tag or weight for child2
            int             pad_3;
        } bin_tree;
        """
        empty_node = Structure("bin_tree", bin_tree_header)
        preferred_child = lambda node: node.child1 if node.weight1 < node.weight2 else node.child2

        def read_node(dbg, address):
            data = dbg.read(address, len(empty_node))
            node = empty_node.copy()
            node.address = address
            node.load(data)
            node.value = chr(node.value)
            return node

        def parse_tree_recursively(dbg, address, index = 0):
            node = read_node(dbg, address)
            node.index = index
            if node.child1 == 0:
                return node
            if node.weight1 < node.weight2:
                node.child1 = parse_tree_recursively(dbg, node.child1, index = (node.index + 1) * 2 - 1)
            else:
                node.child2 = parse_tree_recursively(dbg, node.child2, index = (node.index + 1) * 2)
            return node

        def tree_to_nodes(tree):
            nodes = []
            while tree != 0:
                nodes.append(tree)
                tree = preferred_child(tree)
            return nodes

        def tree_to_str(tree):
            data = ""
            while tree != 0:
                data += tree.value
                tree = preferred_child(tree)
            return data

        with context.local(binary="./driveway"):
            with Debugger(context.binary) as server_dbg:
                server_dbg.until(CALL_SRAND)
                server_dbg.args[0] = 1749655318 # set the server seeds to skip the bruteforce part of the challenge
                server_dbg.until(SHOW_SECRET)
                server_dbg.ni()
                server_dbg.p.recvuntil(b"This is your driveway, can you follow it?\n")
                secret = server_dbg.p.recvline().decode().strip()

                errors = []
                with Debugger(context.binary) as client_dbg:
                    client_dbg.until(CALL_SRAND)
                    client_dbg.args[0] = 1749655318 # set the server seeds to skip the bruteforce part of the challenge
                    client_dbg.until(TREE_TO_STRING)
                    tree_address = client_dbg.args[0]
                    tree = parse_tree_recursively(client_dbg, tree_address)
                    self.assertEqual(secret, tree_to_str(tree))
                    valid_nodes = tree_to_nodes(tree)
                    client_dbg.until(END_CORRUPT_TREE) # The program corrupts the weights of the tree
                    corrupted_nodes = [read_node(client_dbg, node.address) for node in valid_nodes] # We read the memory again to see which values changed
                    for valid_node, corrupted_node in zip(valid_nodes, corrupted_nodes):
                        if valid_node.weight1 != corrupted_node.weight1:
                            errors.append(valid_node.index)
                    
                server_dbg.c(wait=False)
                for el in errors:
                    
                    server_dbg.p.sendline(str(el).encode() + b" HONDA CIVIC")

                server_dbg.p.sendline(b"TOYOTA COROLLA")
                server_dbg.p.recvline()
                server_dbg.p.recvline()
                result = server_dbg.p.recvline()
                self.assertEqual(result, b'Nice job!\n')

    # Testing symbols addresses
    # @unittest.skip
    def test_structure_symbols(self):
        print("\ntest_structure_symbols: ", end="")

        CALL_SRAND = 0x18b1
        TREE_TO_STRING = 0x1611
        END_CORRUPT_TREE = 0x1b8c
        SHOW_SECRET = 0x1b16

        bin_tree_header = """
        typedef struct bin_tree {
            int             value;   // node value (e.g. a character or integer)
            int             pad_1;
            struct bin_tree *child1;    // first child pointer
            int             weight1;      // tag or weight for child1
            int             pad_2;
            struct bin_tree *child2;    // second child pointer
            int             weight2;      // tag or weight for child2
            int             pad_3;
        } bin_tree;
        """
        empty_node = Structure("bin_tree", bin_tree_header)
        preferred_child = lambda node: node.child1 if node.weight1 < node.weight2 else node.child2

        def read_node(dbg, address):
            data = dbg.read(address, len(empty_node))
            node = empty_node.copy()
            node.address = address
            node.load(data)
            node.value = chr(node.value)
            return node

        def parse_tree_recursively(dbg, address, index = 0):
            node = read_node(dbg, address)
            node.index = index
            if node.child1 == 0:
                return node
            if node.weight1 < node.weight2:
                node.child1 = parse_tree_recursively(dbg, node.child1, index = (node.index + 1) * 2 - 1)
            else:
                node.child2 = parse_tree_recursively(dbg, node.child2, index = (node.index + 1) * 2)
            return node

        def tree_to_nodes(tree):
            nodes = []
            while tree != 0:
                nodes.append(tree)
                tree = preferred_child(tree)
            return nodes

        def tree_to_str(tree):
            data = ""
            while tree != 0:
                data += tree.value
                tree = preferred_child(tree)
            return data

        with context.local(binary="./driveway"):
            with Debugger(context.binary) as dbg:
                dbg.until(CALL_SRAND)
                dbg.args[0] = 1749655318
                dbg.until(TREE_TO_STRING)
                tree_address = dbg.args[0]
                tree = parse_tree_recursively(dbg, tree_address)
                dbg.until(SHOW_SECRET)
                dbg.ni()
                dbg.p.recvuntil(b"This is your driveway, can you follow it?\n")
                secret = dbg.p.recvline().decode().strip()
                self.assertEqual(secret, tree_to_str(tree))
                valid_nodes = tree_to_nodes(tree)
                dbg.until(0x1c3d)
                corrupted_nodes = [read_node(dbg, node.address) for node in valid_nodes]
                for valid_node, corrupted_node in zip(valid_nodes, corrupted_nodes):
                    if valid_node.weight1 != corrupted_node.weight1:
                        # correct the node directly in memory
                        dbg.write_int(valid_node.symbols["weight1"], valid_node.weight1)
                        dbg.write_int(valid_node.symbols["weight2"], valid_node.weight2)
                dbg.c(wait=False)
                dbg.p.sendline(b"TOYOTA COROLLA")
                dbg.p.recvline()
                dbg.p.recvline()
                result = dbg.p.recvline()
                self.assertEqual(result, b'Nice job!\n')

if __name__ == "__main__":
    with context.quiet:
        unittest.main()
