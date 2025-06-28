import unittest
import test_old
import test_Structure

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test cases from each file
    suite.addTests(loader.loadTestsFromModule(test_old))
    suite.addTests(loader.loadTestsFromModule(test_Structure))

    # Run all tests quietly
    runner = unittest.TextTestRunner(verbosity=0)
    runner.run(suite)