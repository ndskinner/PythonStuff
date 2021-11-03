# Desc : Imports the latest microsoft azure IP address JSON file, converts CIDR IP address ranges to from and to ranges then created SQL for use
#        with Azure SQL Database firewall
#
# Created By : Andy Skinner
# Date : 14/09/2021
# Version : 1.0
# Change Log :
#

import json
import pandas as pd
import ipaddress as ip
import urllib as url
import requests
import os
from datetime import datetime, timedelta

# Set some variables (filepaths etc)
# Set this to somewhere on disk it`s used for the temporary JSON file
jsonFileName = 'c:\data\ServiceTags_Public.json'
# Set this to somewhere on disk, it`s where the end CSV IP data will be written
outputCSVFile = 'c:\\data\\transIPData.csv'

# Funtion to pass to DF.Apply to get the start or end IP address of the CIDR range
def getIP(CIDR,Position):
    return(ip.ip_network(CIDR)[Position])

# Function to download the JSON file
def downloadIPJson(jsonFileName):
    # Get the start of the current week as MS release a new file every monday and the file name changes depending on the date!
    now = datetime.now()
    fileDateStr = now - timedelta(days = now.weekday())
    fileDateStr = fileDateStr.strftime('%Y%m%d')

    # Get the file, download it and put it in a specific directory
    url = 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_'+fileDateStr+'.json'
    r = requests.get(url)
    with open(jsonFileName,'wb') as outfile:
        outfile.write(r.content)

# Function to create a SQL Server firewall rule string based on a given IP range
def createSQL(ruleName,IPStart,IPEnd):
    return('execute sp_set_database_firewall_rule @name = N\''+ruleName+'_'+str(IPStart)+'_'+str(IPEnd)+'\', @start_ip_address = ' + '\''+str(IPStart) + '\''+ ',' + '@end_ip_address =' +  '\'' + (str(IPEnd)+ '\''))

# Get the latest JSON file
downloadIPJson(jsonFileName)

# Open the IP Address JSON
with open(jsonFileName) as f:
       jsonPayload = json.load(f)

# Normalise and flatten the specific JSON elements (IP addresses, regions and products)
IPData = pd.json_normalize(jsonPayload['values'],record_path=['properties','addressPrefixes'],meta=['name',['properties','region']])

# Check if it`s a valid IP address (i.e. IPv4 only, and add a flag column
IPData['IsInvalid'] = IPData[0].str.contains('::')

# Filter the IP addresses for valid IPv4 ones
filteredIPData = IPData.query('IsInvalid == 0')

# Add a new column with a start IP address for each CIDR in the dataframe
filteredIPData['IPStart'] = filteredIPData[0].apply(getIP,Position=0)
# Add a new column with an end IP address for each CIDR in the dataframe
filteredIPData['IPEnd'] = filteredIPData[0].apply(getIP,Position=-1)
# Add a new column with SQL Stored Proc Code
filteredIPData['spCommand'] = filteredIPData.apply(lambda row: createSQL(row['name'],row['IPStart'],row['IPEnd']),axis=1)

# Output the CSV file
filteredIPData.to_csv(outputCSVFile,index=False)





