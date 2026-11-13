Stage 1 — Baseline Inspection

Project: Custom Network Packet Sniffer and Analyzer
Stage: 1 — Baseline Inspection
Date: 12 November 2026
Status: Completed

# Stage 1 — Baseline Inspection

## 1. Objective

I conducted the baseline inspection to understand the internal workflow and architecture of my Custom Network Packet Sniffer and Analyzer before proceeding with controlled experiments.

My primary objective was to examine how the GUI and main application code interact during packet capture, parsing, processing, traffic analysis, and presentation.

I also wanted to understand the software environment and dependencies, identify potential architectural weaknesses, and observe how the application behaves under different conditions and edge cases.

Establishing this baseline was important because I wanted to identify existing limitations and distinguish them from issues that might emerge during subsequent experiments. It also helped me determine whether the application was sufficiently functional to proceed with controlled testing.

## 2. System and Software Environment

### 2.1 Testing Environment

I documented the following environment in which I conducted the initial inspection and experiments.

| Component | Configuration |
|---|---|
| Operating System | Kali Linux |
| Architecture | x86_64 |
| Kernel | 7.0.12-kali-amd64 |
| Python | 3.13.14 |
| Scapy | 2.8.0 |
| GUI Framework | Tkinter |
| Reference Capture Tool | tcpdump |
| Wireless Interface | wlan0 |
| Loopback Interface | lo |
| Local IPv4 Address | 192.168.1.x |
| Default Gateway | 192.168.1.x |

### 2.2 Environment Selection

I documented the testing environment to understand the system requirements, dependencies, and operating conditions under which the application was being tested.

This information also provides context for interpreting experimental results and helps make the testing process reproducible.

### 2.3 Network Interface Selection

I selected two network interfaces for the initial capture experiments.

**Loopback Interface (`lo`)**

I used the loopback interface to investigate packet capture behaviour when the machine communicates with itself. This allowed me to examine local traffic without depending on an external network connection.

**Wireless Interface (`wlan0`)**

I used the wireless interface to investigate packet capture behaviour during communication over the actual network. This allowed me to examine traffic exchanged between my machine and the network gateway.

Testing both interfaces helped me investigate differences between local host communication and network-based communication.

### 2.4 Reference Capture Utility

I selected `tcpdump` as an independent reference utility to compare its packet capture observations against those produced by my application.

An application running without errors does not necessarily mean that it is capturing and processing packets correctly. Comparing observations with an independent capture utility provides additional evidence for evaluating packet counts and packet-processing behaviour under controlled conditions.

### 2.5 Privilege Requirements and Security Considerations

During initial testing, I found that Scapy packet capture failed when executed as a normal user because the process lacked the permissions required to open a raw packet socket.

Running the capture process with elevated privileges using `sudo` allowed the operation to succeed.

On Linux, raw packet socket access generally requires the `CAP_NET_RAW` capability.

However, running an entire application with unrestricted root privileges increases the potential impact if the application is compromised. An attacker who gains control of a privileged process may be able to misuse the permissions available to it.

This highlighted the importance of the principle of least privilege: an application should receive only the permissions necessary for its operations.

For future security improvements, separating privileged packet capture from the GUI and other application components is worth considering.

## 3. Source Code and Architecture Inspection

### 3.1 Development Contribution and Inspection Scope

I implemented the core application logic in `main.py` with guidance from ChatGPT. The GUI implementation in `GUI.py` was generated with ChatGPT.

The automated test code was also generated with AI assistance. I executed the tests and observed and evaluated their results as part of the baseline inspection.

During this stage, I inspected the source code to understand the application's workflow, how its components interact, and how packet information moves through the application.

### 3.2 Application Workflow

I examined `main.py` and `GUI.py` to understand the two execution workflows supported by the application.

**GUI Workflow**

When I run the application through the graphical interface, Scapy's `AsyncSniffer` captures network traffic asynchronously.

The captured packets are passed through the packet parsing and processing stages. The application then makes the processed traffic information and analysis results available to the GUI.

The GUI refreshes its displayed information approximately every 100 milliseconds, allowing it to update while packet capture continues.

**CLI Workflow**

When I run the application through `main.py`, Scapy's synchronous `sniff()` function is used.

The application captures and processes packets before displaying the resulting information in the terminal.

Unlike the GUI, the CLI does not need to maintain a graphical event loop or continuously handle interface events during packet capture.

### 3.3 Asynchronous Capture and GUI Responsiveness

I used `AsyncSniffer` in the GUI workflow to prevent blocking packet capture from interfering with Tkinter's main event loop.

Calling the normal blocking `sniff()` function directly on the GUI thread could prevent the interface from responding until the capture operation finishes.

Asynchronous capture allows the GUI to continue handling user interactions, rendering the window, and refreshing displayed traffic information while packet capture runs independently.

However, asynchronous capture alone does not guarantee GUI responsiveness under heavy processing loads. The workload involved in packet processing and interface updates can still affect performance.

### 3.4 Separation of Responsibilities

The application separates its functionality into different responsibilities, including:

- Packet capture
- Packet parsing
- Packet processing
- Traffic analysis and summarisation
- GUI presentation

I structured the core application logic around separate responsibilities to improve code organisation and make debugging and testing easier.

This separation also helps narrow down the possible source of a failure. Instead of investigating the entire application for every issue, individual components can be examined independently.

Modularity can reduce complexity and improve maintainability, although it does not automatically eliminate duplicated code or integration problems.

### 3.5 Pre-Experiment Inspection

Before proceeding to controlled experiments, I reviewed the application's architecture, execution workflows, and initial functional state to understand its existing behaviour and limitations.

This helped me establish a baseline for subsequent experiments and distinguish previously identified limitations from newly observed issues.

## 4. Automated Testing Baseline

### 4.1 Testing Approach

I used automated testing to establish an initial functional baseline before proceeding with controlled experiments.

I initially executed individual test files to examine component-level behaviour and identify failures within specific areas. This made it easier to narrow down potential problems without investigating the entire application.

After testing individual components, I executed the complete test suite using Python's unittest discovery mechanism.

### 4.2 Test Suite Overview

The existing test suite contains 122 tests distributed across 12 test files.

The tests cover several application components and functionalities, including:

- Configuration validation
- Packet parsing
- Packet processing
- Interface discovery
- Packet-capture workflows
- Traffic analysis
- Port-scan detection
- GUI workflows and features

The tests primarily use simulated packet data and mocked components. This provides controlled and repeatable inputs for evaluating individual functions without depending entirely on live network traffic.

### 4.3 Test Execution and Results

I executed individual test files first and subsequently ran the complete test suite using:

`PYTHONPATH=. python -m unittest discover -s tests -v`

The complete test execution produced the following results:

| Metric | Result |
|---|---:|
| Total tests | 122 |
| Passed | 122 |
| Failed | 0 |
| Errors | 0 |
| Execution time | 0.263 seconds |

All 122 tests passed without failures or errors.

### 4.4 Interpretation of Results

The passing test results showed that the tested components met the expected outcomes under the specific conditions represented by the automated test cases.

Testing individual components separately helped narrow down the possible source of failures, while running the complete suite provided an overall result for the collected tests.

However, these results do not establish that the application is completely bug-free or reliable under every possible condition.

The tests primarily use simulated packets and mocked components. Simulated inputs are predictable and controlled, whereas actual network traffic can introduce unexpected packet structures, varying traffic rates, timing differences, and other conditions that may expose issues not covered by the test suite.

Additionally, I used AI assistance to generate the test code. My role was primarily to execute the tests and observe their pass/fail results rather than independently designing and authoring every test case.

### 4.5 Testing Limitations and Readiness Assessment

I did not consider the 122 passing tests sufficient evidence to declare the application ready for deployment.

Instead, I treated the results as an initial functional baseline that justified proceeding to controlled experiments.

Further investigation was necessary to evaluate actual packet-capture behaviour, accuracy, performance, and reliability under real network conditions.

### 4.6 Conclusion

The automated testing stage established an initial baseline for the application. All 122 tests passed, indicating that the behaviours covered by the existing test suite worked under the tested conditions.

However, the limitations of simulated inputs and mocked components meant that further testing with actual network traffic was necessary.

I therefore considered the application ready to proceed to controlled experiments, rather than declaring it fully validated or deployment-ready.
