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

"""abgw_bridge_cmd.py: Command line tool for translating ACABELLA format
described schemes to ABGW inputs"""

import sys
import argparse
sys.path.insert(0, "../../core")

from parse_config import ParseConfig
from generate_abgw_inputs import generate_abgw_input

if __name__ == "__main__":
    print("[*] ABGW bridge cmd tool")

    parser = argparse.ArgumentParser(prog = "abgw_bridge",
                                     description = "abgw_bridge transforms the description of an ABE scheme into a valid input for the ABGW tool")
    parser.add_argument("json_input", 
                        type=str, 
                        help='The description of the ABE scheme using the ACABELLA format in JSON')
    
    args = parser.parse_args()
    
    print("[!] Processing " + args.json_input)

    # parse json input

    parse_json = ParseConfig() 
    parse_json.init(args.json_input)

    abgw_params = parse_json.generate_abgw_bridge_params()

    # prepare output for ABGW tool
    
    generate_abgw_input(abgw_params["key"], abgw_params["k_encodings"], abgw_params["c_encodings"], abgw_params["gp_encodings"], abgw_params["unknown"], abgw_params["known"])


