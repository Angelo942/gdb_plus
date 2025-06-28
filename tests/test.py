import unittest
import test_old
import test_Structure
import test_new_libdebug

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test cases from each file
    suite.addTests(loader.loadTestsFromModule(test_old))
    suite.addTests(loader.loadTestsFromModule(test_Structure))
    suite.addTests(loader.loadTestsFromModule(test_new_libdebug))

    # Run all tests quietly
    runner = unittest.TextTestRunner(verbosity=0)
    runner.run(suite)