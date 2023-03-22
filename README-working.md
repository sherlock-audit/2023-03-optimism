# Optimism Bedrock Update contest details

- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the issue page in your private contest repo (label issues as Medium or High)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)

# Reward structure

- $120k contest pot ($70k in OP tokens, 50k USDC)
- 40k USDC to Lead Senior Watsons (obront and Trust)
- $6k USDC allocated to judging ($3.5k in OP tokens, 2.5k USDC)
- The exchange rate of OP tokens will be the 30-day weighted average beginning at the start date of the contest
and ending 30 days after the start date of the contest, using a well-known exchange rate aggregator such as CoinGecko
- All rewards are guaranteed in this contest, there are no Medium/High severity thresholds to unlock more of the pot

# Judging changes from the previous Optimism contest

- Issue de-duplication and initial judging will be handled by a Lead Judge (TBD) approved by Sherlock and Optimism.
- Final decisions on judging will be made by Sherlock (in consultation with the Lead Judge and Optimism). 
- Judging criteria for High and Medium issues will attempt to mirror the judging criteria of the last Optimism contest. In the event of gaps in the previous judging criteria, the [Sherlock judging rules](https://docs.sherlock.xyz/audits/watsons/judging) will be consulted. 
- Low severity issues are not accepted
- Similar to the first contest, this contest will not count towards Leaderboard rankings for any Watsons (due to non-Solidity code, etc.). 

# On-chain context

### OPTIMISM TODO: Verify that this is roughly the way Watsons can think about issues related to these specific topics
```
DEPLOYMENT: mainnet
ERC20: All tokens with regular behavior
ERC721: All tokens with regular behaviour
ERC777: none
FEE-ON-TRANSFER: none
REBASING TOKENS: none
```

# System context

### OPTIMISM TODO: Update for new Goerli deployment, etc. if relevant

For this competition, you’ll be looking at Optimism on the [Goerli network.](https://community.optimism.io/docs/developers/bedrock/public-testnets/#goerli) This system was [recently upgraded](https://community.optimism.io/docs/developers/bedrock/public-testnets/#goerli) from our legacy system to the new [Bedrock architecture](https://community.optimism.io/docs/developers/bedrock/how-is-bedrock-different/). 

Unlike a typical Sherlock competition, rather than looking for bugs in source code, you’ll be able to interact with a live system, complete with block explorers and other infrastructure.

It also opens the door to issues that might result from errors made during the deployment and upgrade process.

Our system is composed of of both Golang and Solidity. Given the size of the code base, we’ll do our best to guide you towards the kinds of bugs we anticipate you might find, and where to look for them.

# Scope

### OPTIMISM TODO: Update scope for latest commit hash. 
The key components of the system can be found in our monorepo at commit [3f4b3c3281](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9). 

- [L1 Contracts](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/L1)
- [L2 Contracts (AKA Predeploys)](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/L2)
- [op-node](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9/op-node)
- [op-geth](https://github.com/ethereum-optimism/op-geth) (in its own repo)

# Resources

The following resources will be useful for helping to understand the system.

### OPTIMISM TODO: LINK TO DESCRIPTION OF UPDATES MADE SINCE THE LAST CONTEST
- [How optimistic rollups and Optimism work](https://community.optimism.io/docs/protocol/2-rollup-protocol/#), including differences between the legacy and bedrock systems.
- [Plain english specs for Optimism](https://github.com/ethereum-optimism/optimism/blob/f30376825c82f62b846590487fe46b7435213d37/specs/README.md)
- [Overview of the diff between op-geth and upstream geth](https://op-geth.optimism.io/)
- A list of [predeployed L2 contracts](https://github.com/ethereum-optimism/optimism/blob/f30376825c82f62b846590487fe46b7435213d37/specs/predeploys.md#L48)
- Guide to [running an Optimism node](https://community.optimism.io/docs/developers/bedrock/node-operator-guide/) on [Goerli](https://community.optimism.io/docs/developers/bedrock/public-testnets/)
- [Goerli Etherscan](https://goerli.etherscan.io/) and [Optimism Goerli Etherscan](https://goerli-optimism.etherscan.io/)
- Previous audit reports can be a useful source of ideas for where to look, and what to look for. They can be found in the [Optimism monorepo](https://github.com/ethereum-optimism/optimism/tree/develop/technical-documents/security-reviews) or directly via the links below (dates given are from the start of the engagement). These audits are also outlined, along with other bedrock related security initiatives, in this [blog post](https://dev.optimism.io/bedrock-security/).
    - Sherlock Bedrock contest, [January 2023](https://github.com/sherlock-audit/2023-01-optimism-judging/issues)
    - Zeppelin review of early Bedrock contracts, [April 2022](https://github.com/ethereum-optimism/optimism/blob/develop/technical-documents/security-reviews/2022_05-Bedrock_Contracts-Zeppelin.pdf)
    - Trail of Bits review of the Rollup Node and Optimistic Geth, [April 2022](https://github.com/ethereum-optimism/optimism/blob/develop/technical-documents/security-reviews/2022_05-OpNode-TrailOfBits.pdf)
    - Sigma Prime review of the Rollup Node and Optimistic Geth, [June 2022](https://github.com/ethereum-optimism/optimism/blob/develop/technical-documents/security-reviews/2022_08-Bedrock_GoLang-SigmaPrime.pdf)
    - Zeppelin review of the ERC20 and ERC721 Bridge, [July 2022](https://github.com/ethereum-optimism/optimism/blob/f30376825c82f62b846590487fe46b7435213d37/technical-documents/security-reviews/2022_09-Bedrock_and_Periphery-Zeppelin.pdf)
    - Trail of Bits invariant definition and testing engagement, [September 2022](https://github.com/ethereum-optimism/optimism/blob/develop/technical-documents/security-reviews/2022_11-Invariant_Testing-TrailOfBits.pdf)
    - Trail of Bits review of final Bedrock updates, [November 2022](https://github.com/ethereum-optimism/optimism/blob/develop/technical-documents/security-reviews/2023_01-Bedrock_Updates-TrailOfBits.pdf)

# Known issues

### OPTIMISM TODO: If there are any other known issues to add, please add them. Best thing to do is probably to go through the [last contest's](https://github.com/sherlock-audit/2023-01-optimism-judging/issues) High and Medium findings, and label each one as either "Will Fix" or "Won't Fix." Then we can update this section to say "Any open High/Medium issue in the last contest repo that is labeled "Won't Fix" will not be rewarded in this contest. Any open High/Medium issue labeled "Will Fix" will only be rewarded if the issue still exists (with an explanation of why the issue still exists or why the fix was improper).

The following issues are known and will not be accepted as valid findings:

1. There is an edge case in which ETH deposited to the `OptimismPortal` by a contract can be irrecoverably stranded:
    
    When a deposit transaction fails to execute, the sender's account balance is still credited with the mint value. However, if the deposit's L1 sender is a contract, the `tx.origin` on L2 will be [aliased](https://github.com/ethereum-optimism/optimism/blob/develop/specs/deposits.md#address-aliasing), and this aliased address will receive the minted on L2. In general the contract on L1 will not be able to recover these funds. 
    
    We have documented this risk and encourage users to take advantage of our CrossDomainMessenger contracts which provide additional safety measures.
    
2. Some of the ‘legacy’ events in the `L1StandardBridge` and `L2StandardBrige` do not emit when expected.
3. If the L1CrossDomainMessenger is paused, withdrawals sent to it will fail and not be replayable.

# What to look for

### OPTIMISM TODO: Update the sections below (or add sections) for any new attack types, etc. if relevant

In order to guide you, we've attempted to outline as clearly as possible the the types of attacks we'd like you to pursue. Issues which do not match those described below will be considered, but are not guaranteed to be accepted. 

The remainder of this document is subdivided into sections based on the type of attack and then outlines the different severity attacks with

# Client node vulnerabilities

The critical client node components are the op-node and op-geth services, which are written primarily in Go.

## High

- Bypass the deposit fee logic, causing the sequencer to improperly mint ETH on Optimism
    - **Explanation:** The op-node service reads events which are emitted by the Optimism Portal contract on L1, and parses those events in order to create deposit transactions which can mint ETH on L2. This attack would require fooling this logic into minting ETH, without actually having to deposit ETH into the Optimism Portal contract.

## Medium

- Consensus failures
    - **Explanation:** There is one sequencer (running the op-node and batcher services) submitting transaction batches to L1, but many verifier op-nodes will read these batches and check the results of its execution. The sequencer and verifiers must remain in consensus, even in the event of an L1 reorg. 
    In addition, verifiers may operate in two different modes meaning that they either read “unsafe” blocks from the Sequencer, or only derive the L2 state from L1. Verifiers in either of these modes should all eventually agree about the finalized head.
    Similarly, a verifier which is syncing the chain from scratch should agree with a verifier which has been running and is likely to have handled L1 reorgs.
- DoS attacks on critical services
    - **Explanation:** Any untrusted inputs which can result in a crash or otherwise cause a denial of service in the op-node or op-geth. Attack surfaces include but are not limited to P2P payloads, RPC payloads, and blockchain state. Moreover, the network should even be robust against batches which could be posted by a malicious sequencer.

# EVM equivalence vulnerabilities

Bedrock’s design aims for [EVM equivalence](https://medium.com/ethereum-optimism/introducing-evm-equivalence-5c2021deb306), meaning that smart contract developers should be able to safely deploy the same contracts to Optimism as they would on Ethereum, without concern for differences in the execution.

An example of a bug which occurred in an earlier version of Optimism was an [ETH inflation attack](https://www.saurik.com/optimism.html) which resulted from a difference between the semantics of `SELFDESTRUCT` in Optimism vs. Ethereum.

## High

Findings that break contracts in a way that could cause people to lose funds and could be experienced with relatively high frequency by the average developer, or allows you to mint ETH, modify state of other contracts, generally cause loss of funds.

## Medium

Findings that break contracts but are difficult to trigger and only impact a very contrived or unusual contract, suggesting that a developer would have to go significantly out of their way to trigger the issue. 

# Bridge vulnerabilities

Naturally the security of our bridging contracts is critical as it holds all assets deposited from L1, and controls the creation of assets on L2.

## High

- Successfully replay a previously completed withdrawal
    - **Explanation:** Because our bridge contracts are being upgraded from a previous state, it’s possible that a misconfiguration could cause previously completed withdrawals to be replayed. This attack class is similar to the [Nomad bridge vulnerability](https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd).
- Forge a withdrawal proof such that you can prove an invalid withdrawal
    - **Explanation:** We have a Solidity implementation of the Merkle Patricia Tree. Can you trick it into verifying the existence of a withdrawal which does not exist? This type of attack would be similar to that of the [Binance Bridge attack](https://www.zellic.io/blog/binance-bridge-hack-in-laymans-terms).
- Bypass the two step withdrawal proof logic
    - **Explanation:** In order to mitigate against possible bugs in our withdrawal proof, we’ve introduced a two step withdrawal process which requires users to prove their withdrawal at the beginning of the 7 day waiting period.

# Generic smart contract issues

Some of the most common smart contract vulnerabilities also apply to our system and are critically important to mitigate.

## High

- Authorization bypass issues enabling an attacker to take actions which should be restricted to one of the system’s special actors, ie. Proposer, Challenger or Batch Submitter
- Upgradability proxy and configuration issues enabling an attacker to re-initialize, take control
- Unexpected reverts causing a system lockup. For example getting the system into a state where any call to a function would revert, possible due to an over/underflow, or other issue.

## Medium

- Attacks, including DoS and griefing, leading to temporary freezing of funds in the bridge.

# Migration attacks

During the migration from the legacy system to Bedrock, the Optimism network is temporarily halted, and undergoes a process of ‘state surgery’, which directly modifies the bytecode and storage of certain contracts. 

Migration attacks would involve putting the legacy system into a pre-migration state such that our migration scripts will result in any of the following:

## High

- ETH is minted or destroyed as a result of the migration.

## Medium

- Contract state which does not match the legacy system (aside from that which is clearly intended to be modified)
    - If this results in loss of funds or another high severity issue, it will be considered as such.
