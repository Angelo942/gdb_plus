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
    @timeout_decorator.timeout(QUICK)
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
    @timeout_decorator.timeout(QUICK)
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

    # Testing if export can handle lists of Structure, Array, float and bytes
    # @unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_structure_comparison(self):
        print("\ntest_structure_comparison: ", end="")
        
        Address_structure = """
            typedef struct {
                char street[50];
                char city[30];
                char country[30];
            } Address;
        """

        Employee_structure = """
            typedef struct {
                int id;
                char name[40];
                char pad[4];
                double salary;
            } Employee;
        """

        Company_structure = Address_structure + Employee_structure + """
            typedef struct {
                char* name;
                Address *office_address;                  // pointer to a nested Address
                Employee employees[5]; // array of Employee structs
                int employee_count;
            } Company;
        """

        with context.local(binary="./structures_folder/company"):
            with Debugger(context.binary) as dbg:
                dbg.until("total_payroll")
                company_pointer = dbg.args[0]
                company = Structure("Company", Company_structure, address=company_pointer)
                company.load(dbg.read(company_pointer, len(company)))
                company.name = String(dbg.read_string(company.name), address=company.name)
                empty_employee = Structure("Employee", Employee_structure)
                company.employees = [empty_employee.copy().load(company.employees.to_bytes(len(empty_employee)*5, "little")[i*len(empty_employee):(i+1)*len(empty_employee)]) for i in range(5)]
                for employee, salary in zip(company.employees, [55000.00, 62000.00, 58000.00, 60000.00]):
                    employee.salary = salary
                office_address = Structure("Address", Address_structure, address=company.office_address)
                office_address.load(dbg.read(office_address.address, len(office_address)))
                company.office_address = Array([office_address], address=office_address.address)
                self.assertEqual(company, dbg.read(company_pointer, len(company)))
                self.assertEqual(company, Structure("Company", Company_structure).load(dbg.read(company_pointer, len(company))))

    # Testing if assigning a list to a pointer creates the correct objects 
    # @unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_structure_array_assignment(self):
        print("\ntest_structure_array_assignment: ", end="")
        
        Address_structure = """
            typedef struct {
                char street[50];
                char city[30];
                char country[30];
            } Address;
        """

        Employee_structure = """
            typedef struct {
                int id;
                char name[40];
                char pad[4];
                double salary;
            } Employee;
        """

        Company_structure = Address_structure + Employee_structure + """
            typedef struct {
                char* name;
                Address *office_address;
                Employee employees[5];
                int employee_count;
            } Company;
        """

        with context.local(binary="./structures_folder/company"):
            with Debugger(context.binary) as dbg:
                dbg.until("total_payroll")
                company_pointer = dbg.args[0]
                company = Structure("Company", Company_structure, address=company_pointer)
                company.load(dbg.read(company_pointer, len(company)))
                company.name = dbg.read_string(company.name)
                office_address = Structure("Address", Address_structure, address=company.office_address)
                office_address.load(dbg.read(office_address.address, len(office_address)))
                company.office_address = office_address
                self.assertEqual(company, dbg.read(company_pointer, len(company)))
                self.assertEqual(company, Structure("Company", Company_structure).load(dbg.read(company_pointer, len(company))))
                self.assertTrue(isinstance(company.office_address, Array))
                self.assertTrue(isinstance(company.name, String))

if __name__ == "__main__":
    with context.quiet:
        unittest.main()
