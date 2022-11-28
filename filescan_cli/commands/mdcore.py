import asyncclick as aclick
from filescan_cli.core.logger import Logger
from filescan_cli.flow.mdcore_scan import MDCoreScanFlow
from filescan_cli.common.config import load_config
from filescan_cli.formatter.mdcore_reports import MDCoreReportsFormatter
import json
import sys
import time
from datetime import datetime


@aclick.group(name='mdcore')
def mdcore():
    pass


@mdcore.command('mdcore', short_help='Integrate with MetaDefender Core as External Scanner or Post Action')
@aclick.option('--config', type=str, is_flag=False, default='', help='Path to the config file')
@aclick.option('--blocked', type=bool, is_flag=True, default=False, help='Process only files marked as Blocked')
@aclick.argument('filename', type=str, required=True)
async def submit(
    config,
    blocked,
    filename
):
    load_config(config)

    logger = Logger()

    # TODO: check existing report based on hash? 
    # md5 = scan_results["file_info"]["md5"]


    data = sys.stdin.readlines()	    
    scan_results = json.loads(data[0])

    result = {}
    if (__will_run_analysis(scan_results, blocked)):

        scan_flow = MDCoreScanFlow()
        original_name = scan_results['file_info']['display_name']
        result = await scan_flow.run(file=filename, link=None, desc='', tags='', prop_tags=False, password='', is_private=False, filename=original_name)     
    else:
          
        result = MDCoreReportsFormatter().empty_result()
                
    # logger.debug(json.dumps(result, indent=3))
    sys.stdout.write(json.dumps(result, indent=3))
    # sys.stdout.write(str(result))
    return result

def __will_run_analysis(scan_results, blockedOnly):

    is_file_blocked = scan_results['process_info']['result'] == "Blocked"    
    return not blockedOnly or (blockedOnly and is_file_blocked)         
    
