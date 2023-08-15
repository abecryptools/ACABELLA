#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""acabella_cmd.py: Command line tool for analyzing ABE schemes
based on JSON inputs"""

import sys
import argparse
sys.path.insert(0, "../../core")

from parse_config import ParseConfig
from analysis import AnalysisWithCorruption
from conditional import ConditionalDecryptionAttack

if __name__ == "__main__":
    print("[*] ACABELLA cmd tool")

    parser = argparse.ArgumentParser()


    parser.add_argument('-a', '--analysis',
                       action='store',
                       choices=['mk', 'da', 'sec', 'cond', 'all', 'comp'],
                       help='Select the type of analysis to perform: mk for master key attack, da for decryption attack, ac17 for security analysis, cond for conditional attack, all for performing every analysis type and comp for only running attacks whenever the scheme is detected as insecure',
                       required="true")

    parser.add_argument('-c', '--config',
                       action='store',
                       help='Configuration file for the analysis type in ACABELLA JSON format',
                       required="true")

    args = parser.parse_args()

    # parse json input

    parse_config = ParseConfig() 
    parse_config.init(args.config)

    # perform analysis

    print("\n\n[*] Analyzing scheme...\n\n")
    
    match str(args.analysis):
        case "mk":
            master_params, corruptable_vars = parse_config.generate_master_key_params()
            analysis = AnalysisWithCorruption()
            analysis.init(master_params, None, corruptable_vars, None, None)
            analysis.run()
            msgs = analysis.show_solution()
            #print("\n" + msgs[0])
        case "da":
                dec_params, corruptable_vars = parse_config.generate_dec_key_params()
                analysis = AnalysisWithCorruption()
                analysis.init(None, dec_params, None, corruptable_vars, None)
                analysis.run()
                msgs = analysis.show_solution()
                print('\n'.join(msgs))
        case "sec":
                security_params = parse_config.generate_security_analysis_params()
                analysis = AnalysisWithCorruption()
                analysis.init(None, None, None, None, security_params)
                analysis.run()
                #print('\n'.join(analysis.show_solution()))
                analysis.show_solution()
        case "cond":
                cd_config = parse_config.generate_conditional_params()
                cd_attack = ConditionalDecryptionAttack()
                cd_attack.init(cd_config["alpha"], cd_config["special_s"], cd_config["mpk"], cd_config["k_fixed"], cd_config["k_att"], cd_config["c_fixed"], cd_config["c_att"], cd_config["unknown"], cd_config["prefixes"], cd_config["nr_indexed_encodings"])
                cd_attack.run()
                msg = cd_attack.show_solution()
                print(msg[0])
        case "all":
                security_params, master_params, corruptable_vars_master, dec_params, corruptable_vars_dec = parse_config.generate_all_params()
                analysis = AnalysisWithCorruption()
                analysis.init(master_params, dec_params, corruptable_vars_master, corruptable_vars_dec, security_params)
                analysis.run()
                msg = analysis.show_solution()
        case "comp":
                security_params, master_params, corruptable_vars_master, dec_params, corruptable_vars_dec = parse_config.generate_all_params()
                analysis = AnalysisWithCorruption()
                analysis.init(master_params, dec_params, corruptable_vars_master, corruptable_vars_dec, security_params)
                analysis.run_logic()
                msg = analysis.show_solution()
        case _:
            pass # should be caught by argparse
