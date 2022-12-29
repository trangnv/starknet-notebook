# Jupyter notebooks to interact with [linear regression competition contracts](https://github.com/trangnv/linear-regression-starknet)

## Setup
- Python environment installation
  ```bash
  python3.9 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```
- Creating starknet account
  - Setup account with [AgentX](https://www.argent.xyz/argent-x/)
  - Get account address and export private key

- `.env` environment variables <br>
Copy the `.env.example` file to a `.env` file and populate each variable (they are all mandatory)
  ```bash
  cp examples/.env.example .env
  ```

## Contracts on Goerli testnet
- Contract address: [0x06e1cb1066945810a7dbbc0550cfc623cc50330014587311d70c653965b59cbe](https://testnet.starkscan.co/contract/0x06e1cb1066945810a7dbbc0550cfc623cc50330014587311d70c653965b59cbe#overview)
- Organizer address: [0x209b55deb9aa39481d5ee1e0b11291908c589305bd54f1148cf201d2f8c1898](https://testnet.starkscan.co/contract/0x0209b55deb9aa39481d5ee1e0b11291908c589305bd54f1148cf201d2f8c1898)


## Data competition flow

### Stage 0
*Organizer*
- Puts training data publicly offchain (GDrive, IPFS, ...)
- Initiates the competition by deploying the contract
- Prepares test data offchain (need to be defined before the competition begins, but not viewable, otherwise participants would overfit it)
- Calculates merkle root of test data
- Commits testing data with that merkle root

Client can use [this](https://github.com/trangnv/starknet-notebook/blob/main/linear-regression-notebooks/organizer.ipynb) Jupyter notebook to calculate commitment/deploy/interact with the contracts


### Stage 1
This phase last 1 week from the moment *organizer* commited test data <br> 
*Competitors*
- Use training data to train model
- Calculate hash of the model
- Commit model with that hash

Client can use [this](https://github.com/trangnv/starknet-notebook/blob/main/linear-regression-notebooks/competitor.ipynb) Jupyter notebook to calculate hash, commit model to the contract. Interacting with contract by Jupyter notebook makes the it seamlessly integrated to machine learning workflow.

### Stage 2
Starts when phase 1 finished <br>
The Jupyter notebooks mentioned above also support these functions invocation

*Competitors*
- Reveal model

*Organizer*
- Reveal testing data


### Stage 3
Now all submission models and testing data are available onchain
*Anyone* can call evaluation function calculate all competitors evaluation metrics and rank them.
