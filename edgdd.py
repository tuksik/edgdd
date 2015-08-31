#!/usr/local/bin/python
# coding: utf8
#
# Copyright (C) 2009,2010,2013 Cyril MORISSE <cmorisse@boxes3.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import logging
import os
import ConfigParser

from optparse import OptionParser, OptionGroup

import gdata.docs.data
import gdata.docs.client

import gdata.spreadsheet.service
import gdata.gauth

__version__ = "edgdd.py v0.5 - juin 2013" 

def export(username, password, docs_name, output_format, dest_path='' ):
    """
    To download we need:
        - filename
        - google doc ressource_id
        - destination path
    """
    logger = logging.getLogger('edgdd')
    try:
        client = gdata.docs.client.DocsClient(source='edggd-v0.5')
        client.ssl = True
        client.http_client.debug = False
        client.ClientLogin(username, password, source=client.source)

        gs_client = gdata.spreadsheet.service.SpreadsheetsService(source='edggd-v0.5')
        gs_client.ClientLogin(username, password, source=gs_client.source)
  
    except gdata.service.BadAuthentication:
        print "Error : Authentification refused by Google. Check supplied username and password."
        sys.exit(-2)
    
    for doc_name in docs_name:
    
        feed = client.GetDocList(uri=("/feeds/default/private/full?title=%s&title-exact=true&max-results=5" % (doc_name,)))
        
        if not feed.entry :
            print "Error : Document '%s' not found !" % (doc_name, )
            sys.exit(-3)

        # now we check query returns only one file
        if len(feed.entry) > 1 :
            print "Warning : Query for '%s' returned %i documents!!!" % (doc_name, len(feed.entry) ) 

        entry_counter =  0
        for entry in feed.entry :
            resource_id = entry.resource_id.text
        
            doc_type = resource_id[:resource_id.find(':')]
            if dest_path:
                dest_path += '/' if dest_path[-1] <> '/' else '' 
            if entry_counter :
                file_path = dest_path+doc_name+'.'+output_format+'.'+str(entry_counter)
            else :
                file_path = dest_path+doc_name+'.'+output_format

            # When downloading a spreadsheet, the authenticated request needs to be
            # sent with the spreadsheet service's auth token.
            if doc_type == 'spreadsheet':
                docs_token = client.auth_token # we save token
                client.auth_token = gdata.gauth.ClientLoginToken(gs_client.GetClientLoginToken())
                client.Export(resource_id, file_path, gid=0)
                client.auth_token = docs_token  # restore the DocList auth token            
                        
            else: # download a doc not a spreadsheet
                client.Export(entry, file_path)

            print "Info : %s exported"  % (file_path,)
            entry_counter+=1


if __name__ == '__main__':
    
    usage = "usage: %prog [options] google_doc_name"
    parser = OptionParser(usage, version=__version__)
    parser.add_option('-d', '--destination-path', dest='dest_path', help="destination directory for exported file", default='')
    parser.add_option('-o', '--output-format', dest='output_format', help="specify export format. Any of (zip, odt, doc, rtf, pdf, txt, xls, csv, ods, ppt, pdf"  )
    # TODO: Compléter les formats dispo à l'export.

    group = OptionGroup(parser, "Identification Options",
                        "Credentials can be specified either via command line or using a"
                        " configuration file.                                                "
                        "When lauched edgdd.py search for a ~/.edgddrc file which must  "
                        "contains:                                                      "
                        "[identification]                                               "
                        "username=name@domain.com                                       "
                        "password=youpassword                                           "
                        "Otherwise credentials can be passed as options using:"
                        )
    group.add_option('-u', '--username',    dest='username', help="google account to use.eg. -u name@googleappsdomain.com")
    group.add_option('-p', '--password',    dest='password', help="password to use")
    parser.add_option_group(group)    
    
    (options, args) = parser.parse_args()
    
    if not args:
        print "\"Google Docs\" Downloader"
        print
        print "    use ./edgdd.py -h or --help for usage instructions."
        print
        sys.exit(0)

    username = None
    password = None

    # we check credentials in ~/.edgdd
    config = ConfigParser.ConfigParser()
    config.read(os.path.expanduser('~/.edgddrc'))
    try:
        username = config.get('identification','username')
        password = config.get('identification','password')
    except:
        pass
    
    # credentials supplied as parameters overwrite those in config file
    if options.username :
        username = options.username
    if options.password :
        password = options.password
    if not username or not password :
        print "Error : username and password not supplied"
        sys.exit(-1) 
    
    output_format = options.output_format
    if output_format not in ('csv', 'xls', 'doc', 'ods', 'html', 'txt', 'rtf', 'pdf', 'odt' ) :
        print "edgdd.py : Error : unknow output format, using pdf"
        output_format = 'pdf'
    
    ret = export( username, password, args, output_format, options.dest_path  )
    sys.exit(ret)
    
