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
  - 
## Contracts on Goerli testnet
- Contract address: [0x06e1cb1066945810a7dbbc0550cfc623cc50330014587311d70c653965b59cbe](https://testnet.starkscan.co/contract/0x06e1cb1066945810a7dbbc0550cfc623cc50330014587311d70c653965b59cbe#overview)
- Organizer address: [0x209b55deb9aa39481d5ee1e0b11291908c589305bd54f1148cf201d2f8c1898](https://testnet.starkscan.co/contract/0x0209b55deb9aa39481d5ee1e0b11291908c589305bd54f1148cf201d2f8c1898)

## Competition phase 0
### Organizer
- Commit test data using [organizer notebook](linear-regression-notebooks/organizer.ipynb)

## Phase 1
### Competitor
- Using [competitor notebook](linear-regression-notebooks/competitor.ipynb) to train model with provided training data as normal data science workflow
  - 1 extra step: export model to `mymodel.txt` which contains the weights
- Commit the model to the contract, details provided in the notebook

## Phase 2
