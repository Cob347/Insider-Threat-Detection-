import pandas as pd
from datetime import datetime

def identify_insider_threats(access_logs_file, sensitive_events, start_date=None, end_date=None, threshold_factor=3):
    """
    Identifies potential insider threats based on access logs.

    Parameters:
    access_logs_file (str): Path to the CSV file containing access logs.
    sensitive_events (list): List of sensitive event types to monitor.
    start_date (datetime, optional): Start date for filtering logs. Defaults to 2022-01-01.
    end_date (datetime, optional): End date for filtering logs. Defaults to 2022-07-01.
    threshold_factor (int, optional): Factor for setting the abnormal activity threshold. Defaults to 3.

    Returns:
    pd.Series: Users with abnormal access to sensitive data or None if no data found.
    """
    if not access_logs_file or not sensitive_events:
        print("Error: Invalid input parameters.")
        return None

    try:
        # Load access logs into a DataFrame
        access_logs = pd.read_csv(access_logs_file)

        # Convert 'eventtime' to datetime
        access_logs['eventtime'] = pd.to_datetime(access_logs['eventtime'])

        # Set default dates if not provided
        if start_date is None:
            start_date = datetime(2022, 1, 1)
        if end_date is None:
            end_date = datetime(2022, 7, 1)

        # Filter access logs for the specified time period
        access_logs = access_logs[(access_logs['eventtime'] >= start_date) & (access_logs['eventtime'] < end_date)]

        # Group events by user and count occurrences of sensitive events
        user_sensitive_event_counts = access_logs[access_logs['eventtype'].isin(sensitive_events)] \
            .groupby('useridentity')['eventtype'].count()

        if not user_sensitive_event_counts.empty:
            # Set threshold for abnormal activity (mean + threshold_factor * std)
            threshold = user_sensitive_event_counts.mean() + threshold_factor * user_sensitive_event_counts.std()

            # Identify users with abnormal access to sensitive data
            suspected_insiders = user_sensitive_event_counts[user_sensitive_event_counts > threshold]

            return suspected_insiders
        else:
            return None
            
    except FileNotFoundError:
        print(f"Error: File '{access_logs_file}' not found. Please provide a valid file path.")
        return None
    except pd.errors.EmptyDataError:
        print("Error: The access logs file is empty or contains no data.")
        return None
    except KeyError as e:
        print(f"Error: Column '{e}' not found in access logs. Please check the file structure.")
        return None
    except Exception as e:
        print("An error occurred:", e)
        return None
