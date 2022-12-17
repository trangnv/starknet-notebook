# Jupyter notebook to interact with StarkNet contracts

# Setup and usage for [linear regression competition](https://github.com/trangnv/linear-regression-starknet)

## Setup
- Python environment installation
- Creating starknet account
- `.env` environment variables <br>
Copy the `.env.example` file to a `.env` file and populate each variable (they are all mandatory)
```bash
cp examples/.env.example .env
```

## Phase 0
### Organizer
- Commit test data using [organizer notebook](linear-regression-notebooks/organizer.ipynb)

## Phase 1
### Competitor
- Using [competitor notebook](linear-regression-notebooks/competitor.ipynb) to train model with provided training data as normal data science workflow
  - 1 extra step: export model to `mymodel.txt` which contains the weights
- Commit the model to the contract, details provided in the notebook

## Phase 2
