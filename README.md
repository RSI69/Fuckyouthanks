This program scans three timeframes for situations where the RSI percentile is simultaneously extremely low, indicating the asset might be oversold. When this happens, the program flags it as a 'buy' signal.

After buying, it tracks the price and marks a sell when either the price goes up by 40% or drops by 90%. Historical testing shows that in ~99% of cases, the price hits the +40% target rather than the -90% stop-loss.

The RSI parameters and buy/sell parameters are adjustable. They've been set as is after backtesting, but could likely be further optimized to maximize profit. Although, you'd be hard pressed to do so.

My hope is that this gives people some economic freedom.



The ANONToken smart contract is a fully autonomous, privacy-preserving ERC20 token system that enables users to mint a token by sending 0.1 ETH and later burn it to receive ETH anonymously. Upon burning, users specify a stealth address (registered via Merkle proof) along with a signed message to authorize the burn, and the contract schedules a randomized ETH withdrawal to the recipient with a built-in delay. The system uses a withdrawal queue, retry logic, and gas buffer estimation to handle edge cases and ensure reliability. Fees collected during withdrawals go to a predefined fee recipient, and the contract includes logic to periodically update a Merkle root that reflects active pending withdrawals. There are no centralized controllers, admin functions, or relayers, making the protocol entirely on-chain and censorship-resistant. The contract is designed for privacy, simplicity, and full decentralization, with no secrets, external dependencies, or upgradeable mechanisms.
