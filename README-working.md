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

```
DEPLOYMENT: Ethereum and Optimism Mainnet
ERC20: All tokens with regular behavior
ERC721: All tokens with regular behaviour
ERC777: none
FEE-ON-TRANSFER: none
REBASING TOKENS: none
```

# System context

The previous competition looked at contracts deployed on the [Goerli network](https://community.optimism.io/docs/developers/bedrock/public-testnets/#goerli).

As we have not yet upgraded the contracts on Goerli, this compettion will focus on the source code listen in the Scope section below.

# Scope

### OPTIMISM TODO: Update scope for latest commit hash.
The key components of the system can be found in our monorepo at commit [3f4b3c3281](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9).

- [L1 Contracts](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/L1)
- [L2 Contracts (AKA Predeploys)](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/L2)
- [op-node](https://github.com/ethereum-optimism/optimism/tree/3f4b3c328153a8aa03611158b6984d624b17c1d9/op-node)
- [op-geth](https://github.com/ethereum-optimism/op-geth) (in its own repo)

# Resources

The following resources will be useful for helping to understand the system.

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

The following issues are known and will not be accepted as valid findings:

1. There is an edge case in which ETH deposited to the `OptimismPortal` by a contract can be irrecoverably stranded:

    When a deposit transaction fails to execute, the sender's account balance is still credited with the mint value. However, if the deposit's L1 sender is a contract, the `tx.origin` on L2 will be [aliased](https://github.com/ethereum-optimism/optimism/blob/develop/specs/deposits.md#address-aliasing), and this aliased address will receive the minted on L2. In general the contract on L1 will not be able to recover these funds.

    We have documented this risk and encourage users to take advantage of our CrossDomainMessenger contracts which provide additional safety measures.

2. [Sherlock #035](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/35) Memory amplification with small but invalid P2P messages

    The fix for this issue is a WIP, and will be addressed prior to mainnet launch.

    - NOTE: AIMING TO COMPLETE BEFORE START OF THE COMP.

3. [Sherlock #209](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/209), #277: Deposit grieffing by filling up the MAX_RESOURCE_LIMIT

    This issue is _mitigated_ by [PR 5064](https://github.com/ethereum-optimism/optimism/pull/5064), which does not completely
      resolve the issue but does increase the cost of a sustained grieffing attack.
    A more complete fix will require architectural changes.

4. There are various 'foot guns' in the bridge which may arise from misconfiguring a token. Examples include:
    - Having both (or neither of) the local and remote tokens be OptimismMintable.
    - Tokens which dynamically alter the amount of a token held by an account, such as fee-on-transfer and rebasing tokens.
    To minimize complexity our bridge design does not try to prevent all forms of developer and user error.

5. When running in non-archive mode `op-geth` has difficulty executing deep reorgs. We are working on a fix.

## Prior Sherlock findings and fixes

The following is a list of findings from the previous Sherlock Audit, along with their fixes:

- [Sherlock #282](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/282): Client will accept invalid blocks from gossip channels due to insufficient L1BlockInfo decoding
    - Fixed in [PR 4936](https://github.com/ethereum-optimism/optimism/pull/4936)
- [Sherlock #087](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/87): Users withdrawals can be permanently locked (via the reentrancy guard)
    - Fixed in [PR 4919](https://github.com/ethereum-optimism/optimism/pull/4919)
- [Sherlock #080](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/80), #096, #158, #297: Withdrawals with high gas limits can be bricked by a malicious user, permanently locking funds
    - Fixed in [PR 5017](https://github.com/ethereum-optimism/optimism/pull/5017)
- [Sherlock #109](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/109): Malicious user can finalize other’s withdrawal with less than specified gas limit, leading to loss of funds
    - Fixed in [PR 5017](https://github.com/ethereum-optimism/optimism/pull/5017)
- [Sherlock #298](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/298): Incorrect implementation of the _isCorrectTokenPair function
    - Fixed in [PR 4932](https://github.com/ethereum-optimism/optimism/pull/4932)
- [Sherlock #279](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/279): Frame parsing accepts fully missing fields
    - Fixed in [PR 4867](https://github.com/ethereum-optimism/optimism/pull/4867)
- [Sherlock #026](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/26), #055, #057: Funds are frozen if send from L1 -> L2 while the L2XDM is paused
    - Fixed in [PR 4913](https://github.com/ethereum-optimism/optimism/pull/4913)
- [Sherlock #011](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/11), #105, #113, #189, #218, #223, #232: Message passer DoS in migration
    - Fixed in [PR 4861](https://github.com/ethereum-optimism/optimism/pull/4861)
- [Sherlock #235](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/235): Function MigrateWithdrawal() may set gas limit too high for old withdrawals
    - Fixed in [PR 4911](https://github.com/ethereum-optimism/optimism/pull/4911)
- [Sherlock #177](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/177): Crafted p2p spam can render nodes permanently unable to process L2 blocks
    - Fixed in [PR 4873](https://github.com/ethereum-optimism/optimism/pull/4873)
- [Sherlock #051](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/51): Cannot bridge native L2 tokens using withdraw/withdrawTo functions
    - Fixed in [PR 4909](https://github.com/ethereum-optimism/optimism/pull/4909)
- [Sherlock #053](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/53) and #058: Withdrawal transactions can get stuck if output root is reproposed
    - Fixed in [PR 4866](https://github.com/ethereum-optimism/optimism/pull/4866)


# What to look for

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
- Permissionlessly prevent another user from depositing or withdrawing.
    - **Explanation:** Several findings in the previous Sherlock audit (see findings [80](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/80), [87](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/87), and [109](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/109)) identified attacks which would allow an arbitrary user to lock up another user's withdrawal (including the associated data and assets). This would have required an upgrade to intervene and release the withdrawals. We're interested in similar attacks on the deposit path as well.

## Medium

- A system user preventing a user from depositing or withdrawing
    - **Explanation:** Two findings in the previous Sherlock audit (see findings [26](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/26) and [53](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/53)) identified attacks which would allow a system user (ie. the Proposer or Messenger Owner) to lock up a user's withdrawal (including the associated data and assets). This would have required an upgrade to release the withdrawals. We're interested in similar attacks on the deposit path as well.
- Temporarily preventing a user from depositing or withdrawing.
    - **Explanation:** A findings in the previous Sherlock audit (see finding [209](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/209)) identified an attack which would allow an arbitrary user to temporarily prevent another user from depositing (including the associated data and assets) using a grieffing attack. This attack would be costly sustain, but also a significant headache for depositors.
        We're interested in similar attacks on the withdrawal path as well.

# Generic smart contract issues

Some of the most common smart contract vulnerabilities also apply to our system and are critically important to mitigate.

## High

- Authorization bypass issues enabling an attacker to take actions which should be restricted to one of the system’s special actors, ie. Proposer, Challenger or Batch Submitter
- Upgradability proxy and configuration issues enabling an attacker to re-initialize, take control
- Unexpected reverts causing a system lockup. For example getting the system into a state where any call to a function would revert, possible due to an over/underflow, or other issue.

## Medium

- Attacks, including DoS and griefing, leading to temporary freezing of funds in the bridge.

# Migration attacks or bugs

During the migration from the legacy system to Bedrock, the Optimism network is temporarily halted, and undergoes a process of ‘state surgery’, which directly modifies the bytecode and storage of certain contracts.

Migration attacks would involve putting the legacy system into a pre-migration state such that our migration scripts will result in any of the following:

## High

- ETH is minted or destroyed as a result of the migration.

## Medium

- Contract state which does not match the legacy system (aside from that which is clearly intended to be modified)
    - If this results in loss of funds or another high severity issue, it will be considered as such.
- Attacks which enable an arbitrary user to halt the migration process (as in finding [11](https://github.com/sherlock-audit/2023-01-optimism-judging/issues/11)).
