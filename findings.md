### [S-#] Looping through players array to check for duplicates in `PuppyRaffle:enterRaffle` is a potential denial of service (DoS) attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make in the transaction. This means the gas costs for the players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

```javascript
// @audit - DoS attack
for (uint256 i = 0; i < players.length; i++) {
@>            if (players[i] == player) {
                return i;
            }
        }
```

**Impact:** The gas cost for raffle entrants will greatly increase as more playes enter the raffle. Discouraging later users from entering, and causing a rush at the start of the raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big that no one else enters, guaranteeing themselves the win.

**Proof Of Concept:**

If we have two sets of 100 players enter, the gas costs will be as such:
- 1st 100 players : roughly 6503275 gas
- 2nd 100 players: roughly 18995515

This is nearly 3x more expensive for the second 100 players.

<details>
<summary>PoC</summary>

```javascript
function test_DoSAttack() public {
        vm.txGasPrice(1);
        // First 100 players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas cost of the first 100 players:", gasUsedFirst); 

        // Next 100 players
        
        address[] memory players2 = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i + playersNum);
        }
        uint256 gasStartsecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEndSecond = gasleft();
        uint256 gasUsedSecond = (gasStartsecond - gasEndSecond) * tx.gasprice;
        console.log("Gas cost of the second 100 players:", gasUsedSecond); 
        
        assertGt(gasUsedSecond, gasUsedFirst); 
        
    }
```

Output:
```javascript
Ran 1 test for test/PuppyRaffleTest.t.sol:PuppyRaffleTest
[PASS] test_DoSAttack() (gas: 25536833)
Logs:
  Gas cost of the first 100 players: 6503275
  Gas cost of the second 100 players: 18995515

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 80.52ms (77.83ms CPU time)
```
</details>


**Recommended Mitigation:** There are a few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyway, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of wheter a user has already entered. 

```diff
+   mapping(address => uint256) public addressToRaffleId;
+   uint256 pubblic raffleId = 0;
.
.
.
function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle"); //
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           addressToRaffleId[newPlayers[i]] = raffleId;
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for(uint256 1=0; i < newPlayers.length; i++) {
+           require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
-        for (uint256 i = 0; i < players.length - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
    }
```

3. Alternatively, you could use [OpenZeppelins' `EnemurableSet` library](https://docs.openzeppelin.com/contracts/5.x/api/utils#EnumerableSet).