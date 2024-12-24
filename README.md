This program scans three timeframes for situations where the RSI percentile is simultaneously extremely low, indicating the asset might be oversold. When this happens, the program flags it as a 'buy' signal.

After buying, it tracks the price and marks a sell when either the price goes up by 40% or drops by 90%. Historical testing shows that in ~99% of cases, the price hits the +40% target rather than the -90% stop-loss.

The RSI parameters and buy/sell parameters are adjustable. They've been set as is after backtesting, but could likely be further optimized to maximize profit. Although, you'd be hard pressed to do so.

My hope is that this gives people some economic freedom.
