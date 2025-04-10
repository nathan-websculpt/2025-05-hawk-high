-include .env

setup:
	@forge install OpenZeppelin/openzeppelin-contracts --no-commit
	@forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-commit
	@forge install foundry-rs/forge-std --no-commit
	@forge install Cyfrin/foundry-devops --no-commit