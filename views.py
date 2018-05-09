#!/usr/bin/python3
from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, desc, func
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# Google Signin Tutorial: https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin

CLIENT_ID = json.loads(
    open('credentials.json', 'r').read())['web']['client_id']

#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', session=login_session, client_id=CLIENT_ID)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        reponse.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('credentials.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        reponse.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        reponse.headers['Content-Type'] = 'application/json'
        print (response)
        return response
        
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(json.dump("Toeken's user ID does not match given user ID.")
                                 , 401)
        reponse.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dump("Toeken's client ID does not match app's.")
                                 , 401)
        print ("Token's client ID does not match app's.")
        reponse.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['email']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['email'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        #print ('Access Token is None')
        return render_template('logout.html', code='401')
    #print ('In gdisconnect access token is %s', access_token)
    #print ('User name is: ')
    #print (login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    #print ('result is ')
    #print (result)
    email= login_session['email']
    if result['status'] == '200':
        email= login_session['email']
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
    return render_template('logout.html', email=email, code=result['status'])

#JSON APIs to view Catalog Information
@app.route('/catalog.json')
def catalogJSON():
    session = DBSession()

    categories = session.query(Category).all()
    listCate = [l.serialize for l in categories]

    for c in listCate:
        items = session.query(Item).filter_by(category_id=c['id']).all()
        if len(items) > 0:
            c['items'] = [i.serialize for i in items]

    return jsonify(Categories=listCate)


#JSON APIs to view individual category Information
@app.route('/catalog/<string:category_name>.json')
def categoryJSON(category_name):
    session = DBSession()

    category = session.query(Category).filter(
        func.lower(Category.name)==func.lower(category_name)).one()
    
    cateList = [category.serialize]

    items = session.query(Item).filter_by(category_id=cateList[0]['id']).all()
    if len(items) > 0:
        cateList[0]['items'] = [i.serialize for i in items]
    return jsonify(cateList)


@app.route('/')
def showHomePage():
    session = DBSession()
    
    categories = session.query(Category).all()
    
    recent_items = session.query(Item).order_by(
        desc(Item.id)).limit(10).all()
    
    return render_template('index.html', fc=categories,
                           items=recent_items, session=login_session)


@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():
    if 'email' not in login_session:
        return redirect('/login')

    session = DBSession()

    if request.method=="POST":
        result = session.query(Category).filter(
                func.lower(Category.name)==func.lower(request.form['name'])
                ).all()
        if len(result) > 0:
            return ('''<script>function myFunc(){
alert("The category with the same name %s is already in the database.");
window.location.href = "/";}
</script><body onload='myFunc()''>''' % request.form['name'])
        else:
            newCategory = Category(name=request.form['name'])
            session.add(newCategory)
            flash("New category %s created successfully." % newCategory.name)
            session.commit()
            return redirect(url_for('showHomePage'))
    else:
        return render_template('newCategory.html', session=login_session)


@app.route('/catalog/<string:category_name>/edit', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'email' not in login_session:
        return redirect('/login')

    session = DBSession()
    sc = session.query(Category).filter(
            func.lower(Category.name)==func.lower(category_name)).one()
    
    if request.method=="POST":
        result = session.query(Category).filter(
                func.lower(Category.name)==func.lower(request.form['name'])
                ).all()
        if len(result) > 0:            
            return ('''<script>function myFunc(){
alert("The category with the same name %s is already in the database.");
window.location.href = "/";}
</script><body onload='myFunc()''>''' % request.form['name'])
        else:      
            sc.name = request.form['name']
            session.add(sc)
            flash("Category successfully editted as %s." % sc.name)
            session.commit()
            return redirect(url_for('showHomePage'))
    else:
        return render_template('editCategory.html', category=sc, session=login_session)


@app.route('/catalog/<string:category_name>/delete', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'email' not in login_session:
        return redirect('/login')

    session = DBSession()
    sc = session.query(Category).filter(
            func.lower(Category.name)==func.lower(category_name)).one()
    itemCtn = session.query(Item).filter_by(category_id=sc.id).count()
    if request.method=="POST":
        session.delete(sc)
        flash("Category %s deleted successfully." % sc.name)
        session.commit()
        return redirect(url_for('showHomePage'))
    else:
        return render_template('deleteCategory.html', category=sc, ctnItems=itemCtn, session=login_session)


@app.route('/catalog/<string:category_name>/item')
def showItemList(category_name):
    session = DBSession()

    full_category = session.query(Category).all()

    current_category = session.query(Category).filter(
        func.lower(Category.name)==func.lower(category_name)).one()
    
    itemList = session.query(Item).filter_by(
        category_id=current_category.id).all()
    
    return render_template('item.html', items=itemList, i_length=len(itemList),
                           cc=current_category, fc=full_category, session=login_session)


@app.route('/catalog/<string:category_name>/<string:item_name>')
def showItemDetail(category_name, item_name):
    session = DBSession()
    
    current_category = session.query(Category).filter(
        func.lower(Category.name)==func.lower(category_name)).one()
    
    item = session.query(Item).filter(
        Item.category_id==current_category.id, func.lower(Item.name)==func.lower(item_name)).one()
    
    return render_template('item_details.html', item=item, session=login_session)


@app.route('/catalog/<string:category_name>/new', methods=['GET','POST'])
def newItem(category_name):
    if 'email' not in login_session:
        return redirect('/login')

    session = DBSession()
    current_category = session.query(Category).filter(
        func.lower(Category.name)==func.lower(category_name)).one()
    if request.method == 'POST':
        itemToCheck = session.query(Item).filter(
            func.lower(Item.name)==func.lower(request.form['name'])
            ).all()
        if len(itemToCheck) > 0:
            return ('''<script>function myFunc(){
alert("The item with the same name %s is already in the database.");
window.location.href = "/catalog/%s/item";}
</script><body onload='myFunc()''>''' % (request.form['name'], current_category.name))
        else:
            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           category_id=current_category.id);
            session.add(newItem)
            flash("New item %s created successfully." % newItem.name)
            session.commit()
            return redirect(url_for('showItemList', category_name=category_name))
    else:
        return render_template('newItem.html', category=current_category)
        

@app.route('/item/<string:item_name>/edit', methods=['GET','POST'])
def editItem(item_name):
    if 'email' not in login_session:
        return redirect('/login')

    session = DBSession()
    item = session.query(Item).filter(
        func.lower(Item.name)==func.lower(item_name)).one()
    
    if request.method == 'POST':
        if request.form['name']:
            itemToCheck = session.query(Item).filter(
                func.lower(Item.name)==func.lower(request.form['name'])
                ).all()
            if len(itemToCheck) > 0:
                return ('''<script>function myFunc(){
alert("The item with the same name %s is already in the database.");
window.location.href = "/catalog/%s/item";}
</script><body onload='myFunc()''>''' % (request.form['name'], item.category.name))
            else:
                item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            category = session.query(Category).filter(
                func.lower(Category.name)==func.lower(request.form['category'])).one()
            item.category_id = category.id
        session.add(item)
        session.commit()
        flash("Item successfully edited as %s" % item.name)
        return redirect(url_for('showHomePage'))
    else:
        categories = session.query(Category).all()
        return render_template("editItem.html", categories=categories, item=item)


@app.route('/item/<string:item_name>/delete', methods=['GET','POST'])
def deleteItem(item_name):
    if 'email' not in login_session:
        return redirect('/login')

    session = DBSession()
    item = session.query(Item).filter(
        func.lower(Item.name)==func.lower(item_name)).one()
    
    if request.method == 'POST':
        flash("%s Item successfully deleted " % item.name)
        session.delete(item)
        session.commit()
        return redirect(url_for('showHomePage'))
    else:
        return render_template("deleteItem.html", item=item)


def createUser(login_session):
    session=DBSession()
    newUser = User(name=login_session['username'], email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user=session.query(User).filter_by(email=login_session['email']).all()
    for u in user:
        print (u.id)
        print (u.email)
    return user[0].id


def getUserInfo(user_id):
    session=DBSession()
    user=session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    session=DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None;


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)
