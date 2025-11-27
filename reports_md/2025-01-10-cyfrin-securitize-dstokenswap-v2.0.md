**Lead Auditors**

[Hans](https://twitter.com/hansfriese)
**Assisting Auditors**



---

# Findings
## Medium Risk


### Meta transactions will not work due to direct msg.sender usage in validateLockedTokens

**Description:** The protocol makes use of `_msgSender()` in several parts and it is understood the protocol team considers possible support of meta transactions where relayers will handle the transactions that are signed by the investors.
But the `validateLockedTokens` function uses `msg.sender` directly to check the available balance for transfer. This prevents the contract from supporting meta transactions since the actual token holder's address would be different from the relayer's address (msg.sender) in a meta transaction context.
```solidity
81  function validateLockedTokens(string memory investorId, uint256 value, IDSRegistryService registryService) private view {
82      IDSComplianceService complianceService = IDSComplianceService(sourceServiceConsumer.getDSService(sourceServiceConsumer.COMPLIANCE_SERVICE()));
83      IDSComplianceConfigurationService complianceConfigurationService = IDSComplianceConfigurationService(sourceServiceConsumer.getDSService(sourceServiceConsumer.COMPLIANCE_CONFIGURATION_SERVICE()));
84
85      string memory country = registryService.getCountry(investorId);
86      uint256 region = complianceConfigurationService.getCountryCompliance(country);
87
88      // lock/hold up validation
89      uint256 lockPeriod = (region == US) ? complianceConfigurationService.getUSLockPeriod() : complianceConfigurationService.getNonUSLockPeriod();
90      uint256 availableBalanceForTransfer = complianceService.getComplianceTransferableTokens(msg.sender, block.timestamp, uint64(lockPeriod));//@audit-issue msg.sender can be different from _msgSender
91      require(availableBalanceForTransfer >= value, "Not enough unlocked balance");
92  }
```
Note that in the function `ComplianceServiceRegulated::getComplianceTransferableTokens()`, the first parameter `_who` is used to get investor info by ` getRegistryService().getInvestor(_who);`.
```solidity
@securitize\digital_securities\contracts\compliance\ComplianceServiceRegulated.sol
658:     function getComplianceTransferableTokens(
659:         address _who,
660:         uint256 _time,
661:         uint64 _lockTime
662:     ) public view override returns (uint256) {
663:         require(_time != 0, "Time must be greater than zero");
664:         string memory investor = getRegistryService().getInvestor(_who);
665:
666:         uint256 balanceOfInvestor = getLockManager().getTransferableTokens(_who, _time);
667:
668:         uint256 investorIssuancesCount = issuancesCounters[investor];
669:
670:         //No locks, go to base class implementation
671:         if (investorIssuancesCount == 0) {
672:             return balanceOfInvestor;
673:         }
674:
675:         uint256 totalLockedTokens = 0;
676:         for (uint256 i = 0; i < investorIssuancesCount; i++) {
677:             uint256 issuanceTimestamp = issuancesTimestamps[investor][i];
678:
679:             if (uint256(_lockTime) > _time || issuanceTimestamp > (_time - uint256(_lockTime))) {
680:                 totalLockedTokens = totalLockedTokens + issuancesValues[investor][i];
681:             }
682:         }
683:
684:         //there may be more locked tokens than actual tokens, so the minimum between the two
685:         uint256 transferable = balanceOfInvestor - Math.min(totalLockedTokens, balanceOfInvestor);
686:
687:         return transferable;
688:     }
```
In other parts, `msg.sender` and `_msgSender()` are being used correctly to handle the meta transactions.

**Impact:** For meta transactions, `getComplianceTransferableTokens` will return incorrect value because `msg.sender` is not necessarily the investor. Users would always need to have ETH to pay for gas, which defeats one of the main benefits of meta transactions where users could have their transactions relayed by others.

**Recommended Mitigation:** Use `_msgSender()` instead of using `msg.sender` in the specific part as belows.

```diff
    function validateLockedTokens(string memory investorId, uint256 value, IDSRegistryService registryService) private view {
        IDSComplianceService complianceService = IDSComplianceService(sourceServiceConsumer.getDSService(sourceServiceConsumer.COMPLIANCE_SERVICE()));
        IDSComplianceConfigurationService complianceConfigurationService = IDSComplianceConfigurationService(sourceServiceConsumer.getDSService(sourceServiceConsumer.COMPLIANCE_CONFIGURATION_SERVICE()));

        string memory country = registryService.getCountry(investorId);
        uint256 region = complianceConfigurationService.getCountryCompliance(country);

        // lock/hold up validation
        uint256 lockPeriod = (region == US) ? complianceConfigurationService.getUSLockPeriod() : complianceConfigurationService.getNonUSLockPeriod();//@audit-info assume these values are representing time duration in seconds
--        uint256 availableBalanceForTransfer = complianceService.getComplianceTransferableTokens(msg.sender, block.timestamp, uint64(lockPeriod));
++        uint256 availableBalanceForTransfer = complianceService.getComplianceTransferableTokens(_msgSender(), block.timestamp, uint64(lockPeriod));

        require(availableBalanceForTransfer >= value, "Not enough unlocked balance");
    }
```

**Securitize:** Fixed in commit [b26a16](https://bitbucket.org/securitize_dev/bc-dstoken-class-swap-sc/commits/b26a167524dfa96fc92dc18a863998a50e533bf2).

**Cyfrin:** Verified.


\clearpage
## Informational


### Missing zero address validation in initialize function

**Description:** The `initialize` function in `DSTokenClassSwap` contract does not validate that the input addresses `_sourceDSToken` and `_targetDSToken` are non-zero addresses.

```solidity
DSTokenClassSwap.sol
40:     function initialize(address _sourceDSToken, address _targetDSToken) public override onlyProxy initializer {
41:         __BaseDSContract_init();
42:         sourceDSToken = IDSToken(_sourceDSToken);//@audit-issue INFO check zero address
43:         sourceServiceConsumer = IDSServiceConsumer(_sourceDSToken);
44:         targetDSToken = IDSToken(_targetDSToken);
45:         targetServiceConsumer = IDSServiceConsumer(_targetDSToken);
46:     }
```

**Recommended Mitigation:** Add zero address validation checks.

**Securitize:** Fixed in commit [b26a16](https://bitbucket.org/securitize_dev/bc-dstoken-class-swap-sc/commits/b26a167524dfa96fc92dc18a863998a50e533bf2).

**Cyfrin:** Verified.


\clearpage