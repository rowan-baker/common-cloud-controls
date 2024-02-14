
Scenario - Human readable + ID
Given: RDMS instance
And: Taxonomy feature
When: A "<THREAT ACTOR>" requests/ enacts attack x
and: request is successful
Then: MITRE REF
And: ATT&Ck STAGE
And: loss of <Service> <subservice> C/I/A


# Common Cloud Controls RDMS MITRE Resilience Feature
@CCC-RDMS-MITRE
Feature: Relational Database Management System MITRE Resilience
    As a decision-maker or regulator for a financial services organization
    I want to ensure that an RDMS system is resilient to threat tactics and techniques documented within MITRE ATT&CK for the service to be portable with other RDMS systems
    So that I can ensure that the system is not locked into a single vendor

    Background:
        Given a RDMS system is reachable from a known endpoint
        And Test data inserted to the table successfully 
        And credentials have been supplied with sufficient permissions to create a new table and user


    @CCC-RDMS-1-threat #SQL Support - Properly handle queries in the SQL language.
    # Scenario: T1190 Exploit Public Facing application
    Scenario: T1059 Command and Scripting Interpreter
        Given: Taxonomy feature  CCC-RDMS-1 SQL handling
        When: The following query is executed "<QUERY>"
        Then: they system returns an expected value: "<RESPONSE>"
        And: the confidentiality, integrity, availability of the database is affected.

    # These are largely random at present, and should be refined further
    Examples:
        | QUERY                                    | RESPONSE   |
        | TBC                                      | TBC        | 

    Scenario: T1078 Valid Accounts
        Given: An RDMS Instance
        And: RDMS instance is internet facing
        When: Authentication Credential is compromised
        When: The following query is executed "<QUERY>"
        Then: they system returns an expected value: "<RESPONSE>"
        And: confidentiality, integrity and availability of the database is affected

    # These are largely random at present, and should be refined further
    Examples:
        | QUERY                                    | RESPONSE   |
        | SELECT name FROM employees LIMIT 1       | John Smith |
        | SELECT age FROM employees WHERE id = 1   | 35         |
        | SELECT COUNT(*) FROM orders              | 5          |
        | SELECT product_name FROM products WHERE price > 50 LIMIT 1 | "Widget" |
        | SELECT orders.order_id, customers.customer_name FROM orders INNER JOIN customers ON orders.customer_id = customers.customer_id | 1, "John Smith" |
        | SELECT employees.employee_name, departments.department_name FROM employees LEFT JOIN departments ON employees.department_id = departments.department_id | "John Smith", "Sales" |
        | SELECT department, AVG(salary) as avg_salary FROM employees GROUP BY department | "Sales", 50000 |
        | SELECT department, AVG(salary) as avg_salary FROM employees GROUP BY department HAVING AVG(salary) > 50000 | "Sales", 60000 |
        | SELECT product_name, price FROM products ORDER BY price DESC | "Widget", 100 |
        | SELECT department, COUNT(*) as employee_count FROM employees GROUP BY department ORDER BY employee_count DESC | "Sales", 3 |



    @CCC-RDMS-2-threat #Ensure the system supports vertical scaling


    @CCC-RDMS-3-threat #Ensure the system supports horizontal scaling via read replicas

    
    @CCC-RDMS-4-threat #Ensure the system supports horizontal scaling via read replicas in multiple regions

    @CCC-RDMS-5-threat #Ensure the system supports automated backups
    Scenario: T1537 Transfer Data to Cloud Account
        Given: An RDMS Instance
        And: An RDMS administrator Role
        When: An on Demand Backup/Snapshot is requested by the administrator
        And: The backup destination is in a cloud storage resource outside of the organisations control
        And: the request is successful
        Then: confidentiality of the database is affected


    @CCC-RDMS-6-threat #Ensure the system supports point in time recovery
    Scenario: T1490 Inhibit System Recovery
        Given: An RDMS Instance
        And: An RDMS administrator Role
        When: On Demand Backup/Snapshot is deleted by the administrator
        And: the request is successful
        Then: availability of the database backups are affected  

    Scenario: T1490 Inhibit System Recovery
        Given: An RDMS Instance
        And: An RDMS administrator Role
        When: On Demand Backup/Snapshot are disabled by the administrator
        And: the request is successful
        Then: availability of the database backups are affected  



    @CCC-RDMS-7-threat #Ensure the system supports encryption at rest
    Scenario T1486 Data Encrypted for Impact
        Given: An RDMS Instance
        And: system supports encryption at rest
        When: A "<THREAT ACTOR>" requests encryption of DB instance with imported key material
        And: the request is successful
        And: Threat actor revokes cloud provider access to key material
        Then: availability of the database is affected
    
    Scenario: T1490 Inhibit System Recovery
        Given: An RDMS Instance
        And: Encryption enabled
        When: A "<THREAT ACTOR>" requests revocation of DB access to Encryption Keys
        And: the request is successful
        Then: availability of the database is affected
    
    Scenario: T1490 Inhibit System Recovery
        Given: An RDMS Instance Backup
        And: Encryption enabled
        When: A "<THREAT ACTOR>" requests revocation of backup access to Encryption Keys
        And: the request is successful
        Then: availability of the database backup is affected

    | Threat Actor |
    | Unprivileged Insider |
    | Privileged Insider |
    | Authenticated Internet based attacker with leaked credential |
    | Unauthenticated Internet based attacker |


    @CCC-RDMS-8-threat - Ensure the system supports encryption in transit
    Scenario: T1040 - Network Sniffing
        Given: An RDMS Instance
        When: A "<THREAT ACTOR>" MITM DB network traffic
        Then: confidentiality, integrity and availability of RDMS is affected
    
    @CCC-RDMS-9-threat - Ensure the system supports role based access control
    Scenario: T1110 - Brute Force
        Given: An RDMS Instance
        And: Local User/PW authentication
        When: An unauthenticated internet attacker executes a password spraying attack
        And: Is successful
        Then: confidentiality, integrity and availability of RDMS is affected


    @CCC-RDMS-10-threat
    Scenario: T1562.008 Impair Defenses: Disable or Modify Cloud logs
        Given: An RDMS instance
        And: @CCC-RDMS-10 Ensure the system supports logging
        When: A "<THREAT ACTOR>" requests disabling of logging
        And: request is successful
        Then: availability of RDMS logging is compromised



    | Threat Actor |
    | Unprivileged Insider |
    | Privileged Insider |
    | Authenticated Internet based attacker with leaked credential |

    @CCC-RDMS-11
    Scenario: Ensure the system supports monitoring
        When monitoring is enabled
        Then the system returns the expected value
    
    @CCC-RDMS-12
    Scenario: Ensure the system supports alerting
        When alerting is enabled
        Then the system returns the expected value
    
    @CCC-RDMS-13
    Scenario: Ensure the system can support failover
        When the system has a standby database configured
        And the primary database has become unreachable
        Then the system should use the standby system instead
