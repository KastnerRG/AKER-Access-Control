# AKER-Access-Control
This repo is a companion to [this paper](https://arxiv.org/pdf/2106.13263.pdf). 
## Summary
Modern systems on a chip (SoCs) utilize heterogeneous architectures where multiple IP cores have concurrent access to on-chip shared resources. In security-critical applications, IP cores have different privilege levels for accessing shared resources, which must be regulated by an access control system. AKER is a design and verification framework for SoC access control. AKER builds upon the Access Control Wrapper (ACW) -- a high performance and easy-to-integrate hardware module that dynamically manages access to shared resources. To build an SoC access control system, AKER distributes the ACWs throughout the SoC, wrapping controller IP cores, and configuring the ACWs to perform local access control. To ensure the access control system is functioning correctly and securely, AKER provides a property-driven security verification using MITRE common weakness enumerations. AKER verifies the SoC access control at the IP level to ensure the absence of bugs in the functionalities of the ACW module, at the firmware level to confirm the secure operation of the ACW when integrated with a hardware root-of-trust (HRoT), and at the system level to evaluate security threats due to the interactions among shared resources. The performance, resource usage, and security of access control systems implemented through AKER is experimentally evaluated on a Xilinx UltraScale+ programmable SoC, it is integrated with the OpenTitan hardware root-of-trust, and it is used to design an access control system for the OpenPULP multicore architecture.

## Repo Structure
```
AKER-Access-Control
|-- docs: Documentation for various aspects of the project (slides, papers, sec-verif reference) 
|-- rtl: RTL files for various acw designs and other ip cores used for testing/validation  
|-- sec_verif: Various scripts and config files used to generate/verify security properties over the RTL designs
    |-- aker_sv
    |-- AKER_ACW.csv
    |-- DEMO_1_AKER_SV.ipynb
    |-- DEMO_2_AKER_SV.ipynb
        
```
