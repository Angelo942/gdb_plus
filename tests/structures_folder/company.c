#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EMPLOYEES 5

// 1) Nested structure: Address
typedef struct {
    char street[50];
    char city[30];
    char country[30];
} Address;

// 2) Array element structure: Employee
typedef struct {
    int id;
    char name[40];
    double salary;
} Employee;

// 3) Main structure: Company
typedef struct {
    char *name;                        // now dynamically allocated
    Address *address;                  // pointer to a nested Address
    Employee employees[MAX_EMPLOYEES]; // array of Employee structs
    int employee_count;
} Company;

// Utility: compute total payroll
double total_payroll(const Company *c) {
    double total = 0.0;
    for (int i = 0; i < c->employee_count; i++) {
        total += c->employees[i].salary;
    }
    return total;
}

int main(void) {
    // --- 1) Zero-initialize the company ---
    Company myCompany;
    memset(&myCompany, 0, sizeof(Company));

    // Allocate and set the name
    const char *company_name = "Acme Widgets Inc.";
    myCompany.name = malloc(strlen(company_name) + 1);
    if (!myCompany.name) {
        perror("malloc");
        return EXIT_FAILURE;
    }
    strcpy(myCompany.name, company_name);

    // Allocate and fill in the Address
    myCompany.address = malloc(sizeof(Address));
    if (!myCompany.address) {
        perror("malloc");
        free(myCompany.name);
        return EXIT_FAILURE;
    }
    strcpy(myCompany.address->street,  "123 Innovation Drive");
    strcpy(myCompany.address->city,    "Amsterdam");
    strcpy(myCompany.address->country, "Netherlands");

    // --- 2) Add some employees ---
    Employee emp_list[] = {
        { 1001, "Alice Janssen",  55000.0 },
        { 1002, "Bob van Dijk",   62000.0 },
        { 1003, "Carla Visser",   58000.0 },
        { 1004, "David Smits",    60000.0 }
    };
    int num_to_add = sizeof(emp_list) / sizeof(emp_list[0]);
    for (int i = 0; i < num_to_add && i < MAX_EMPLOYEES; i++) {
        myCompany.employees[myCompany.employee_count++] = emp_list[i];
    }

    // --- 3) Print out company info ---
    printf("Company: %s\n", myCompany.name);
    printf("Address: %s, %s, %s\n\n",
           myCompany.address->street,
           myCompany.address->city,
           myCompany.address->country);

    printf("Employees (%d):\n", myCompany.employee_count);
    for (int i = 0; i < myCompany.employee_count; i++) {
        Employee *e = &myCompany.employees[i];
        printf("  #%d: %-15s  Salary: €%.2f\n",
               e->id, e->name, e->salary);
    }

    // --- 4) Compute & print total payroll ---
    printf("\nTotal payroll: €%.2f\n", total_payroll(&myCompany));

    // --- 5) Clean up ---
    free(myCompany.address);
    free(myCompany.name);

    return EXIT_SUCCESS;
}
