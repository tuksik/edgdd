**Cloned from https://bitbucket.org/cmorisse/edgdd**
Introduction
============
edgdd allows you to download any Google Documents using a command line script.

edgdd depends on gdata-python-client v2.0.9

edgdd is released under MIT Licence (the same as Google Docs API samples)

Installation
============
	hg clone ssh://hg@bitbucket.org/cmorisse/edgdd
	cd edgdd
	virtualenv .
	source bin/activate
	pip install -r requirements.pip

Configuration
=============
Create a google account. Eg. user@domain.com
Share some documents with this account in read only mode.

Create a ~/.edgddrc file with this content:

	[identification]
	username=user@domain.com
	password={{insert_password_here}}

Usage
=====
In the virtualenv,

	python edgdd.py --help
	python edgdd.py -o csv hr.employee

