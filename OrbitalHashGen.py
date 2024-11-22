#
# Orbital Intelligence Cyber Threat Assessment Program 
#
# Orbital Guardian Hash Generator
#
# Copyright 2023-2024 Orbital Intelligence LLC
#
# Standard Python libraries (>=3.11)
#
# Run: pip install -r requirements.txt
#
#   pip install tabulate
#   pip install pandas
#   pip install XlsxWriter
#

from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
import argparse
from argparse import RawTextHelpFormatter
from datetime import (datetime, timezone)
import logging
import traceback 
import tabulate
import hashlib
import pandas 

# Program Version 
VERSION = '2024.11.20'
COPYRIGHT = '2024'

# Global Directory settings
utc = datetime.now(timezone.utc)
directoryDate = utc.strftime("%Y.%m.%d_%H.%M") 
filenameDateTime = utc.strftime("%Y.%m.%d_%H.%M.%S") 
baseDirectory = os.path.join(os.getcwd(), 'OrbitalHashGen_Artifacts', directoryDate)
logsDirectory = baseDirectory

# Global logger
log = logging.getLogger(__name__)

# Constants
LOG_FILENAME = os.path.join(logsDirectory, f'OrbitalHashGenLog_{filenameDateTime}z.log')
ORBITAL_GUARDIAN_EXCEL_FILE = f'OrbitalHashGen_{filenameDateTime}z.xlsx'
ORBITAL_GUARDIAN_EXCEL_FILENAME = os.path.join(logsDirectory, ORBITAL_GUARDIAN_EXCEL_FILE)

#
# Class for generating standard crytographic hashes
#
class HashGen:
    data = ''
    sha3_512 = ''
    sha3_256 = ''
    sha2_512 = ''
    sha2_256 = ''
    sha1 = ''
    md5 = ''

    def __init__(self, sourceData):
        self.data = sourceData
        self.sha3_512 = ''
        self.sha3_256 = ''
        self.sha2_512 = ''
        self.sha2_256 = ''
        self.sha1 = ''
        self.md5 = ''

    def GenerateHashes(self):
        objSha3_512 = hashlib.sha3_512()
        objSha3_512.update(self.data.encode('utf-8'))
        self.sha3_512 = objSha3_512.hexdigest()

        objSha3_256 = hashlib.sha3_256()
        objSha3_256.update(self.data.encode('utf-8'))
        self.sha3_256 = objSha3_256.hexdigest()

        objSha2_512 = hashlib.sha512()
        objSha2_512.update(self.data.encode('utf-8'))
        self.sha2_512 = objSha2_512.hexdigest()

        objSha2_256 = hashlib.sha256()
        objSha2_256.update(self.data.encode('utf-8'))
        self.sha2_256 = objSha2_256.hexdigest()

        objSha1 = hashlib.sha1()
        objSha1.update(self.data.encode('utf-8'))
        self.sha1 = objSha1.hexdigest()

        objMd5 = hashlib.md5()
        objMd5.update(self.data.encode('utf-8'))
        self.md5 = objMd5.hexdigest()

def ConfigureLogging():
    logging.basicConfig(format='%(asctime)s - %(message)s', 
                        level=logging.WARNING, 
                        encoding='utf-8',
                        datefmt='%Y-%m-%d %H:%M:%S', 
                        handlers=[logging.FileHandler(filename=LOG_FILENAME, encoding='utf-8', mode='w'),
                                  logging.StreamHandler()
                                 ]
                       )

def GenerateHashArtifactExcelFile(objHashGen, destFile):
    #
    # Saves the hash data to a formatted Excel file 
    #

    log.debug('')
    log.debug(f'Executing GenerateHashArtifactExcelFile [{os.path.basename(destFile)}]...')

    # Set the default column width
    columnWidth = 18

    # Prepare data object
    data = {
        'Algorithm': ['SHA3-512','SHA3-256','SHA2-512','SHA2-256','SHA1','MD5'],
        'Hash': [objHashGen.sha3_512,objHashGen.sha3_256,objHashGen.sha2_512,objHashGen.sha2_256,objHashGen.sha1,objHashGen.md5]
    }

    # Create a pandas data frame
    dfArtifactsSummary = pandas.DataFrame(data)

    # Get the shape of the data
    log.debug(f'dfArtifactsSummary shape (r,c):  {dfArtifactsSummary.shape}')
    asRowCount, asColumnCount = dfArtifactsSummary.shape
    log.debug(f'asRowCount:    {asRowCount}')
    log.debug(f'asColumnCount: {asColumnCount}')
    log.debug(f'')
    log.debug(f'{dfArtifactsSummary.to_markdown()}')

    # Export the data to Excel
    with pandas.ExcelWriter(destFile, engine='xlsxwriter') as xlsxWriter:  
        #
        # Write the hash data to the worksheet
        #
        dfArtifactsSummary.to_excel(xlsxWriter, sheet_name='Hash Data', index=False, startrow=1, header=False)

        # Get the xlsxwriter workbook and worksheet objects
        workbook  = xlsxWriter.book

        # Define various formatting options
        formatRed = workbook.add_format({'bg_color':'#C00000', 'font_color': 'white', 'bold': True})
        formatBlue = workbook.add_format({'bg_color':'#4472C4', 'font_color': 'white', 'bold': True})
        formatGreen = workbook.add_format({'bg_color':'#70AD47', 'font_color': 'white', 'bold': True})
        formatPurple = workbook.add_format({'bg_color':'#7030A0', 'font_color': 'white', 'bold': True})
        formatLightGray = workbook.add_format({'bg_color':'#BFBFBF', 'font_color': 'black'})
        formatBold = workbook.add_format({'bold': True})
        textWrap = workbook.add_format({'valign':'top', 'text_wrap':'true'})
        verticalTop = workbook.add_format({'valign':'top'})
        verticalTopCenter = workbook.add_format({'valign':'top', 'align':'center'})
        # Add a format. Light red fill with dark red text.
        formatRedHighlight = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
        # Add a format. Green fill with dark green text.
        formatGreenHighlight = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'})
        # Add a format. Yellow fill with dark green text.
        formatYellowHighlight = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C5700'})
        # Add a format. Purple fill with dark green text.
        formatPurpleHighlight = workbook.add_format({'bg_color': '#CC99FF', 'font_color': '#7030A0'})
        # Add a format. Dark Blue fill with white text.
        formatDarkBlueHighlight = workbook.add_format({'bg_color': '#44546A', 'font_color': '#FFFFFF'})
        # Add a format. Blue fill with dark blue text.
        formatBlueHighlight = workbook.add_format({'bg_color': '#8EA9DB', 'font_color': '#203764'})
        # Add a format. Gray fill with dark gray text.
        formatGrayHighlight = workbook.add_format({'bg_color': '#D9D9D9', 'font_color': '#262626'})

        asWorksheet = xlsxWriter.sheets['Hash Data']

        # Set the header format and create table
        asColumnSettings = [{'header': column} for column in dfArtifactsSummary.columns]
        asWorksheet.add_table(0, 0, asRowCount, asColumnCount - 1, {'columns': asColumnSettings, 'style': 'Table Style Medium 2'})
        asWorksheet.set_column(0, asColumnCount - 1, columnWidth)

        # Apply general format to the header row
        formatHeaderRow = workbook.add_format({'rotation': 0, 'align': 'center', 'valign': 'top'})
        asWorksheet.set_row(0,25,formatHeaderRow)

        asColumns = dfArtifactsSummary.columns

        # Apply specific format to a header cells
        formatRedHeader = workbook.add_format({'rotation': 0, 'align': 'center', 'valign': 'top', 'bg_color':'#C00000', 'font_color': 'white', 'bold': True})
        formatGreenHeader = workbook.add_format({'rotation': 0, 'align': 'center', 'valign': 'top', 'bg_color':'#70AD47', 'font_color': 'white', 'bold': True})

        # Apply header formatting 
        asWorksheet.write('A1', asColumns[0], formatRedHeader)      # algorithm
        asWorksheet.write('B1', asColumns[1], formatGreenHeader)    # hash

        # Set desired column widths for specific fields 
        asWorksheet.set_column('A:A', 15, verticalTop)  # algorithm
        asWorksheet.set_column('B:B', 125, verticalTop) # hash


def PrintHashData(objHashGen):
    #
    # Prints the hash data to the console and log file in a table format  
    #

    # Build the hash data table
    hashTable = []
    headerRowSummary = ['Algorithm','Hash']
    hashTable.append(headerRowSummary)

    # Prepare and populate a table data structure with the hash details
    item = ['SHA3-512', objHashGen.sha3_512]
    hashTable.append(item)
    item = ['SHA3-256', objHashGen.sha3_256]
    hashTable.append(item)
    item = ['SHA2-512', objHashGen.sha2_512]
    hashTable.append(item)
    item = ['SHA2-256', objHashGen.sha2_256]
    hashTable.append(item)
    item = ['SHA1', objHashGen.sha1]
    hashTable.append(item)
    item = ['MD5', objHashGen.md5]
    hashTable.append(item) 

    # Print hash details
    log.critical(f'')
    log.critical(f'=====================')
    log.critical(f'Hash Details')
    log.critical(f'=====================')
    log.critical(f'\n{tabulate.tabulate(hashTable, headers="firstrow", tablefmt="fancy_grid")}')
    log.critical(f'')


def main():
    #
    # Setup logging
    #

    # Confirm local logging directory exists, create it if necessary
    logPath = os.path.dirname(LOG_FILENAME)
    if not os.path.exists(logPath):
        os.makedirs(logPath)
    # Configure logger settings
    ConfigureLogging()

    #
    # Proceed with the program
    #

    log.critical("     ____       __    _ __        __   ____      __       __")
    log.critical("    / __ \\_____/ /_  (_) /_____ _/ /  /  _/___  / /____  / /")
    log.critical("   / / / / ___/ __ \\/ / __/ __ `/ /   / // __ \\/ __/ _ \\/ / ")
    log.critical("  / /_/ / /  / /_/ / / /_/ /_/ / /  _/ // / / / /_/  __/ /  ")
    log.critical("  \\____/_/  /_.___/_/\\__/\\__,_/_/  /___/_/ /_/\\__/\\___/_/   ")
    log.critical("")
    log.critical("##############################################################")
    log.critical("01001111 01110010 01100010 01101001 01110100 01100001 01101100")
    log.critical("01001111 01110010 01100010 01101001 01110100 01100001 01101100")
    log.critical("==============================================================")
    log.critical("")
    log.critical("                        Orbital Intel                         ")
    log.critical("                    Orbital Hash Generator                    ")
    log.critical("")
    log.critical("==============================================================")
    log.critical("01001111 01110010 01100010 01101001 01110100 01100001 01101100")
    log.critical("01001111 01110010 01100010 01101001 01110100 01100001 01101100")
    log.critical("##############################################################")
    log.critical("")
    log.critical(f'Copyright (c) {COPYRIGHT} Orbital Intelligence LLC')
    log.critical(f"Version {VERSION}")
    log.critical("")

    # Configure and Process command line arguments
    parser = argparse.ArgumentParser(description="OrbitalHashGen - Orbital Intel Hash Generation Utility\
	\n\nGenerates standard cryptographic hashes for string data (such as passwords) to facilitate Orbital Intelligence research and analysis."
		, prog='OrbitalHashGen.py'
		, formatter_class=RawTextHelpFormatter)

    parser.add_argument('sourcedata', help=f'Provide the data to be hashed')
    parser.add_argument("--verbose",  "-v", action="store_true", help="Flag to display verbose output \nVerbose output is disabled by default")
    args = parser.parse_args()

    # Apply the verbose output setting
    if args.verbose:
        log.level=logging.DEBUG

    # Collect the source data to hash
    sourceData = args.sourcedata

    try:
        # Get the current datetime
        startUtcDatetime = datetime.now(timezone.utc)
        startLocalDatetime = datetime.now()

        # Display program configuration data
        log.critical('')
        log.debug(f"Source Data:       {len(sourceData)}")
        log.critical(f"Excel Output File: {os.path.basename(ORBITAL_GUARDIAN_EXCEL_FILENAME)}")
        log.critical('')

        # Generate Hashes
        log.info('Generating hashes')
        objHashData = HashGen(sourceData=sourceData)
        objHashData.GenerateHashes()

        # Generate Excel results file
        GenerateHashArtifactExcelFile(objHashGen=objHashData, destFile=ORBITAL_GUARDIAN_EXCEL_FILENAME)

        # Print hash data details to console
        PrintHashData(objHashGen=objHashData)


    except KeyboardInterrupt:
        log.critical('')
        log.critical('#############################################')
        log.critical('OrbitalHashGen.py aborted by user.')
        log.critical('#############################################')
        sys.exit(0)
    except Exception as error:
        log.critical('#############################################')
        log.critical('General Error during OrbitalHashGen.py processing.')
        log.critical('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        log.critical(f'Error: {error}')
        log.critical(f'Call Stack:\n{traceback.format_exc()}')
        log.critical('#############################################')
    finally: 
        # Execution completed 
        endUtcDatetime = datetime.now(timezone.utc)
        endLocalDatetime = datetime.now()

        executionTime = endLocalDatetime-startLocalDatetime
        log.critical('')
        log.debug(f'OrbitalHashGen processing started at:   {startLocalDatetime}L / {startUtcDatetime}Z')
        log.debug(f'OrbitalHashGen processing completed at: {endLocalDatetime}L / {endUtcDatetime}Z')
        log.debug('')
        log.critical(f'OrbitalHashGen processing time:   {executionTime} ')
        log.critical('')
        log.critical(f'Excel file:  {ORBITAL_GUARDIAN_EXCEL_FILENAME}')
        log.critical('')
        log.critical(f'Log file:    {LOG_FILENAME}')
        log.critical('')
        log.critical('######################################################')
        log.critical('OrbitalHashGen completed.   ')
        log.critical('######################################################')


if __name__ == "__main__":
    main()



