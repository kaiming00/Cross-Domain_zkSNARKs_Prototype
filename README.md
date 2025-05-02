## Introduction
In this project, a consortium blockchain and zkSNARKs are utilized to construct an interactive simulation process for one-way cross-domain authentication in a real machine environment. Additionally, the method of marking points is adopted to record the time delay for analysis.  

## System Architecture
This project includes the Proxy Authentication Server A and Verification Server 1 running on PC1, the Proxy Authentication Server B and Verification Server 2 running on PC2, and User A running on a Raspberry Pi.

## Installation Tutorial
1. Launch the Hyperledger Fabric blockchain network with three nodes on both PC1 and PC2.
2. Deploy the chaincode onto the blockchain.
3. Modify the corresponding local machine addresses in each project file.
4. Package each project file into a JAR package respectively and then deploy them onto PC1, PC2, and the Raspberry Pi.
5. Run the corresponding JAR packages on PC1 and PC2.
6. Finally, execute User A on the Raspberry Pi, which means that User A initiates the authentication and completes it.

## Instructions for Use
The test version of Hyperledger Fabric is v2.3, which includes 2 organizations, 3 orderers, 4 peers, and two CLIs. The consensus algorithm is etcdraft (users can change it according to their needs).
The chaincode is written in nodejs v12.16.1.
User A in the Raspberry Pi is written based on openjdk 11. 
