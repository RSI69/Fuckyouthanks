from ta.momentum import RSIIndicator
import pandas as pd
import requests
import os
from ta.momentum import RSIIndicator

# Code 1
api_endpoint_pairs = 'https://api.kraken.com/0/public/AssetPairs'
response_pairs = requests.get(api_endpoint_pairs)
pairs_data = response_pairs.json().get('result')

if pairs_data:
    usd_pairs = [pair for pair, info in pairs_data.items() if 'USD' in info['altname']]
    usd_pairs_csv_path = r'C:\Users\xx\python\Crypto\kraken_pairs.csv'
    pd.DataFrame(usd_pairs, columns=['pair']).to_csv(usd_pairs_csv_path, index=False)

    result_df = pd.DataFrame(columns=['symbol', 'time', 'close'])

    api_endpoint_ohlc = 'https://api.kraken.com/0/public/OHLC'
    interval = 60
    since_timestamp = 0

    for usd_pair in usd_pairs:
        params_ohlc = {
            'pair': usd_pair,
            'interval': interval,
            'since': since_timestamp
        }

        response_ohlc = requests.get(api_endpoint_ohlc, params=params_ohlc)
        data_ohlc = response_ohlc.json().get('result', {}).get(usd_pair)

        if data_ohlc:
            pair_df = pd.DataFrame(data_ohlc, columns=['time', 'open', 'high', 'low', 'close', 'vwap', 'volume', 'count'])
            pair_df['symbol'] = usd_pair
            result_df = pd.concat([result_df, pair_df[['symbol', 'time', 'close']]])

    os.remove(r'C:\Users\xx\python\Crypto\kraken_price_data.csv')
    output_ohlc_csv_path = r'C:\Users\xx\python\Crypto\kraken_price_data.csv'
    result_df.to_csv(output_ohlc_csv_path, index=False)

# Read the output of Code 1
code1_output_path = r'C:\Users\xx\python\Crypto\kraken_price_data.csv'
code1_df = pd.read_csv(code1_output_path)

# Read the existing CSV file
existing_csv_path = r'C:\Users\xx\python\Crypto\kraken_price_data_combined.csv'
existing_df = pd.read_csv(existing_csv_path)

# Union the two DataFrames
union_df = pd.concat([code1_df, existing_df])

# Remove duplicates based on 'symbol' and 'time'
union_df = union_df.drop_duplicates(subset=['symbol', 'time'])

# Sort by 'symbol' and 'time' in ascending order
union_df = union_df.sort_values(by=['symbol', 'time'])

# Save the unioned and deduplicated DataFrame to a new CSV file
os.remove(r'C:\Users\xx\python\Crypto\kraken_price_data_combined.csv')
output_combined_csv_path = r'C:\Users\xx\python\Crypto\kraken_price_data_combined.csv'
union_df.to_csv(output_combined_csv_path, index=False)

# Set the desired decimal places
decimal_places = 11
union_df['Short_RSI'] = union_df.groupby('symbol')['close'].transform(lambda x: round(RSIIndicator(x, window=720).rsi(), decimal_places)) 
union_df['Long_RSI'] = union_df.groupby('symbol')['close'].transform(lambda x: round(RSIIndicator(x, window=1440).rsi(), decimal_places)) 
union_df['Super_Long_RSI'] = union_df.groupby('symbol')['close'].transform(lambda x: round(RSIIndicator(x, window=2160).rsi(), decimal_places)) 

# Columns to convert to float64 with 4 decimals
columns_to_convert = ['close', 'Short_RSI', 'Long_RSI', 'Super_Long_RSI']

# Convert the specified columns to float64 with 4 decimals
union_df[columns_to_convert] = union_df[columns_to_convert].round(11).astype('float64')

# Sort the data by symbol and time in ascending order
union_df.sort_values(['symbol', 'time'], inplace=True)

# List of symbols to exclude
symbols_to_exclude = ['USTUSD', 'USTUSDC', 'USTUSDT', 'USDCUSD', 'USDCUSDT', 'USDCAUD', 'USDCCAD', 'USDCCHF', 'USDCEUR', 'USDCGBP', 'USDCHF', 
                      'DAIUSD', 'DAIUSDT', 'DOTUSDT', 'ETHUSDT', 'ETHWUSD', 'PYUSDUSD', 'ZUSDZCAD', 'TUSDUSD','USDTAUD', 'PYUSDEUR', 
                      'USDTEUR', 'USDTJPY', 'ZGBPZUSD', 'ZEURZUSD', 'EURTUSDT', 'USDTGBP']

# Create a boolean mask based on symbols_to_exclude
mask = ~union_df['symbol'].isin(symbols_to_exclude)

# Apply the mask to filter out unwanted symbols
union_df = union_df[mask]

# Get unique symbols in the dataset
symbols = union_df['symbol'].unique()

import dask.dataframe as dd
from multiprocessing import cpu_count

# Define the metadata structure for the output DataFrame
meta = {
    'symbol': 'object',
    'time': 'int64',
    'close': 'float64',
    'Short_RSI': 'float64',
    'Long_RSI': 'float64',
    'Super_Long_RSI': 'float64',
    'rsi_short_percentile': 'float64',
    'rsi_long_percentile': 'float64',
    'rsi_super_long_percentile': 'float64',
}

# Convert the pandas DataFrame to a Dask DataFrame
dask_df = dd.from_pandas(union_df, npartitions=cpu_count())

# Define a function to calculate percentiles for each group
def process_group(group):
    group = group.copy()  # Avoid modifying the original group
    group['rsi_short_percentile'] = group['Short_RSI'].expanding().rank(pct=True) * 100
    group['rsi_long_percentile'] = group['Long_RSI'].expanding().rank(pct=True) * 100
    group['rsi_super_long_percentile'] = group['Super_Long_RSI'].expanding().rank(pct=True) * 100
    return group

# Apply the function group by group
dask_df = dask_df.groupby('symbol').apply(process_group, meta=meta)

# Compute the result and convert back to pandas
union_df = dask_df.compute()

# Reset index to resolve ambiguity and avoid conflicts
if 'symbol' in union_df.index.names:
    # Drop the index level `symbol` before resetting the index
    union_df = union_df.reset_index(level='symbol', drop=True)

# Now reset the index normally to avoid any duplicate insertion of `symbol`
union_df = union_df.reset_index()



# Final sorted dataframe
union_df.sort_values(['symbol', 'time'], inplace=True)

# Drop specified columns
union_df = union_df.drop(['Short_RSI', 'Long_RSI', 'Super_Long_RSI'], axis=1)

# Reorder columns
column_order = ['symbol', 'time', 'close', 'rsi_short_percentile', 'rsi_long_percentile', 'rsi_super_long_percentile']
union_df = union_df[column_order]

os.remove(r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_input_unfiltered.csv')
output_csv = r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_input_unfiltered.csv'
union_df.to_csv(output_csv, mode='a', index=False, header=False)

# Drop rows with blank values in the specified columns
union_df = union_df.dropna(subset=['rsi_short_percentile', 'rsi_long_percentile', 'rsi_super_long_percentile'])

# Reset the index after dropping rows
union_df = union_df.reset_index(drop=True)

# Extract unique symbols from the union_df
unique_symbols = union_df['symbol'].unique()

# Create a DataFrame with the unique symbols
unique_symbols_df = pd.DataFrame({'symbol': unique_symbols})

# Write the unique symbols to a CSV file
os.remove(r'C:\Users\xx\python\Crypto\kraken_symbols.csv')
output_symbols_csv_path = r'C:\Users\xx\python\Crypto\kraken_symbols.csv'
unique_symbols_df.to_csv(output_symbols_csv_path, index=False)

os.remove(r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_input.csv')
output_csv = r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_input.csv'
union_df.to_csv(output_csv, mode='a', index=False, header=False)

# Load the data from the CSV file
file_pathx = r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_input.csv'
data = pd.read_csv(file_pathx, header=None)

# Filter symbols with a positive or zero trend based on the first and last price
filtered_data6 = (
    data.groupby(0, group_keys=False)
    .filter(lambda x: x.iloc[-1, 2] >= x.iloc[0, 2])
)

# Remove the original file
os.remove(file_pathx)

# Define the output path and save the filtered data
output_csvw = file_pathx
filtered_data6.to_csv(output_csvw, mode='a', index=False, header=False)

import csv

# Read dataset1 from the CSV file
dataset1_path = r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_input.csv'
dataset1 = []

with open(dataset1_path, 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
    for row in csv_reader:
        dataset1.append(row)

# Remove the header from dataset1
header = dataset1[0]
dataset1 = dataset1[1:]

# Create the equivalent format of dataset2
converted_dataset = []

for row in dataset1:
    # Take the first 6 elements from each row
    symbol, time, close, rsi_short_percentile, rsi_long_percentile, rsi_super_long_percentile = row[:6]

    # Convert the elements to the desired data types
    converted_row = [str(symbol), float(time), float(close), float(rsi_short_percentile), float(rsi_long_percentile), float(rsi_super_long_percentile)]

    # Append the converted row to the dataset
    converted_dataset.append(converted_row)

##########

import pandas as pd

class Trade:
    def __init__(self, action, symbol, date, price):
        self.action = action
        self.symbol = symbol
        self.date = date
        self.price = price


def find_sell(buy_trade, symbol_dataset, price_increase_percent, stop_loss_percent):
    buy_date = buy_trade.date
    buy_price = buy_trade.price
    for i, sell_data in enumerate(symbol_dataset):
        sell_date = sell_data[1]  # Access date from the inner list
        sell_price = sell_data[2]  # Access price from the inner list
        if sell_date > buy_date:
            if (sell_price >= buy_price * (1 + price_increase_percent / 100)) or \
                    (sell_price <= buy_price * (1 - stop_loss_percent / 100)):
                return i, Trade('sell', buy_trade.symbol, sell_date, sell_price)
    return None, None


def process_symbol_trades(symbol, symbol_dataset, x, y, z, price_increase_percent, stop_loss_percent):
    trades = []
    i = 0
    while i < len(symbol_dataset):
        data = symbol_dataset[i]
        _, date, _, percent1, percent2, percent3 = data
        percent1, percent2, percent3 = map(float, [percent1, percent2, percent3])
        if percent1 < x and percent2 < y and percent3 < z:
            action = f'buy({len(trades) + 1})'
            buy_trade = Trade(action, symbol, date, float(data[2]))
            trades.append(buy_trade)
            sell_index, sell_trade = find_sell(buy_trade, symbol_dataset[i + 1:], price_increase_percent, stop_loss_percent)
            if sell_trade:
                trades.append(sell_trade)
                i += sell_index + 1  # Move to the next position after the sell trade
            else:
                break  # No more buy trades for the current symbol, exit the loop
        else:
            i += 1

    return trades


def main(dataset, x, y, z, price_increase_percent, stop_loss_percent):
    symbols = set(data[0] for data in dataset)
    all_trades = []

    for symbol in symbols:
        symbol_dataset = [data for data in dataset if data[0] == symbol]
        symbol_trades = process_symbol_trades(symbol, symbol_dataset, x, y, z, price_increase_percent, stop_loss_percent)
        all_trades.extend(symbol_trades)

    # Create a Pandas DataFrame
    df = pd.DataFrame({
        'Action': [trade.action for trade in all_trades],
        'Symbol': [trade.symbol for trade in all_trades],
        'Date': [trade.date for trade in all_trades],
        'Price': [trade.price for trade in all_trades],
    })

    # Save the DataFrame to a CSV file
    os.remove(r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_output.csv')
    df.to_csv(r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_output.csv', index=False)

dataset = converted_dataset

# Sample conditions
x = .1
y = .1
z = .1
price_increase_percent = 40
stop_loss_percent = 90

# Run the main program
main(dataset, x, y, z, price_increase_percent, stop_loss_percent)

# Load the CSV file into a DataFrame
csv_path = r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_price_data_output.csv'
df = pd.read_csv(csv_path)

# Convert the 'Date' column to datetime format
df['Date'] = pd.to_datetime(df['Date'], unit='s')

# Sort the DataFrame by 'Date' in descending order within each 'Symbol' group
df_sorted = df.sort_values(by=['Date'], ascending=False)

# Save the sorted DataFrame to a CSV file
os.remove(r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_analytics2.csv')
df_sorted.to_csv(r'C:\Users\xx\python\Crypto\kraken_rsi_hourly_experiment_analytics2.csv', index=False)

