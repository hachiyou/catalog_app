# Catalog APP

Build a catalog app using Python Flask framework and Google OAuth2.0 API

## Getting Started

### Prerequisites

Since I wrote this in windows 10, all the software are windows based.  
The required softwares are:

1. [Python 3.6.5](https://wiki.python.org/moin/BeginnersGuide/Download)
2. [Vagrant 2.0.4](https://www.vagrantup.com/downloads.html)
3. [Virtual Box 5.2](https://www.virtualbox.org/wiki/Downloads)
4. [Git Bash](https://git-scm.com/downloads)

### Installation & Setup

1. Download and install all the required software.
2. Download the zip file from <https://github.com/udacity/fullstack-nanodegree-vm> and extract the zip file.
3. Navigate to this folder in Bash using `cd`. Change directory to <b>vagrant</b>
4. Run the command `vagrant up` to download the linux box, run command `vagrant ssh` after successful installation of linux.
5. Download the files in this repository, unzip and place this folder under vagrant.
6. Before you can run this app, you must obtain a client ID from Google.
	1. Visit <https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin> and click on `CONFIGURE A PROJECT` button.
	2. Create a new project or select from the drop down menu, enter a name for this app in the OAuth interface.
	3. Select `Web Server` from the drop down menu, enter <http://localhost:8000/oauth2callback> as the Authorized Redirect URI.
	4. Download the client configuration, rename it to credentials.json and place it in the same folder.
7. Enter `python views.py` inside vagrant bash, access the app using a web browser by the URL <http://localhost:8000>

### Instructions for using the Catalog APP

1. The app is not yet populated with any records yet. Please login and create categories then add items.
2. Users can view the list of items and categories without logging in via Google, but adding, editing and deleting items requires login.
3. Categories and items that have the same name as the ones already in the database will not be able to get added to the database due to the design of the URLs.
4. For direct access using URL, the pattern are as follow:  
	Parameters inside () will need to be replace with actual name.
	* Login: <http://localhost:8000/login>
	* Logout: <http://localhost:8000/gdisconnect>
	* Home Page: <http://localhost:8000/>
	* Add Category: <http://localhost:8000/catalog/new>
	* Edit Category: <http://localhost:8000/catalog/(category_name)/edit>
	* Delete Category: <http://localhost:8000/catalog/(category_name)/delete>
	* Show specific category: <http://localhost:8000/catalog/(category_name)/item>
	* Show specific item: <http://localhost:8000/catalog/(category_name)/(item_name)>
	* Add item: <http://localhost:8000/catalog/(category_name)/new>
	* Edit Item: <http://localhost:8000/item/(item_name)/edit>
	* Delete Item: <http://localhost:8000/item/(item_name)/delete>
	* JSON Endpoints:
		* Overall: <http://localhost:8000/catalog.json>
		* Individual Category: <http://localhost:8000/catalog/(category_name).json>
## Built With

* Python 3.6.5
