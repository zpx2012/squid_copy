import pandas as pd, sys
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib import style
import pytz

def plot_loss_rate(csv_file_path):
    """
    Reads loss rate data from a CSV file and plots Lossrate over time.

    Args:
        csv_file_path (str): The path to the CSV file.
    """
    try:
        # Load the dataset from the specified CSV file
        df = pd.read_csv(csv_file_path)
    except FileNotFoundError:
        print(f"Error: The file '{csv_file_path}' was not found.")
        print("Please make sure the CSV file is in the same directory as the script or provide the full path.")
        return

    # --- Data Preparation ---
    # Convert the 'EpochTime' column from Unix timestamp (seconds) to datetime objects.
    # This is crucial for plotting time-series data correctly.
    df['Time'] = pd.to_datetime(df['EpochTime'], unit='s')
    utc8_timezone = pytz.timezone('Etc/GMT-8')
    df['Time'] = df['Time'].dt.tz_localize('UTC').dt.tz_convert(utc8_timezone)

    # --- Plotting ---
    # Set a visually appealing style for the plot
    style.use('seaborn-v0_8-whitegrid')

    # Create a figure and an axes object for the plot
    fig, ax = plt.subplots(figsize=(15, 7))

    # Plot the 'Lossrate' against the new 'Time' column
    #ax.plot(df['Time'], df['Lossrate'], marker='.', linestyle='-', markersize=8, label='Loss Rate')
    ax.scatter(df['Time'], df['Lossrate'], marker='o', s=50, alpha=0.7, label='Loss Rate')

    # --- Formatting the Axes ---
    # Set the format of the x-axis labels to 'Hour:Minute:Second'
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

    # Rotate date labels for better readability if they overlap
    fig.autofmt_xdate()

    # Set the labels for the x and y axes
    ax.set_xlabel('Time (UTC+8)', fontsize=12)
    ax.set_ylabel('Loss Rate', fontsize=12)

    # Set the title of the plot
    ax.set_title('Loss Rate Over Time', fontsize=16, fontweight='bold')

    # Add a legend to identify the plotted line
    ax.legend()

    # Add a grid for easier value reading
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Ensure the layout is tight and no labels are cut off
    plt.tight_layout()

    # Display the plot
    plt.savefig(csv_file_path.replace('.csv', 'scatter.png'), bbox_inches="tight")

# --- Execution ---
if __name__ == '__main__':
    # Name of the CSV file provided by the user
    file_name = sys.argv[1]
    plot_loss_rate(file_name)

