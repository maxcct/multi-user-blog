import os
import string
import jinja2
import webapp2
import re
from google.appengine.ext import db
import hmac
import hashlib
import random
from post import Post
from post import render_str
from comment import Comment
from user import User
from user import make_salt
from user import make_pw_hash

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

SECRET = 'kwirky'

def hash_str(s):
    """Combines secret string with given string to create secure hash."""
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def check_password(name, entered_pw, pw_hash):
    salt = pw_hash.split(',')[0]
    if pw_hash == make_pw_hash(name, entered_pw, salt = salt):
        return True


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        user = User.get_by_id(val)
        user_hash = str(user.pw_hash).split(',')[1]
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name,
                                         str(val) + '|' + user_hash))

    def read_secure_cookie(self, name):
        """Checks a cookie has not been tampered with."""
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            val = int(cookie_val.split('|')[0])
            password_hash = cookie_val.split('|')[1]
            user = User.get_by_id(val)
            if user:
                user_hash = str(user.pw_hash).split(',')[1]
                if user_hash == password_hash:
                    return cookie_val
                else:
                    return self.redirect("/logout")
            else:
                return self.redirect("/logout")

    def valid_username(self, username):
        return re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)

    def valid_password(self, password):
        return re.compile(r"^.{3,20}$").match(password)

    def valid_email(self, email):
        return re.compile(r"^[\S]+@[\S]+.[\S]+$").match(email)

    def password_match(self, password, verify):
        return password == verify

    def login(self, user):
        self.set_secure_cookie('user_id', user.key().id())

    def username_from_cookie(self):
        """Extracts username from hash stored in cookie."""
        user_cookie = self.request.cookies.get('user_id')
        cookie_user_id = user_cookie.split('|')[0]
        user = User.get_by_id(int(cookie_user_id))
        return user.name

    def validate_author(self, post_id):
        """Checks whether the current user is the author of a given post."""
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        author = post.author
        if self.user:
            if self.user.name == author:
                return True
        else:
            return False

    def validate_comment_author(self, comment_id):
        """Checks whether the current user is the author of a given comment."""
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        author = comment.author
        if self.user:
            if self.user.name == author:
                return True
        else:
            return False

    def post_from_post_id(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        return post

    def comment_from_comment_id(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        return comment

    def delete_post(self, post_id):
        if self.validate_author(post_id):
            post = self.post_from_post_id(post_id)
            post.delete()
            return self.redirect('/blog/myposts')
        else:
            return self.redirect('/login')

    def edit_post(self, post_id):
        if self.validate_author(post_id):
            return self.redirect('/blog/edit/%s' % post_id)
        else:
            return self.redirect('/login')

    def delete_comment(self, post_id):
        comment_id = self.request.POST.get('delete_comment')
        if self.validate_comment_author(comment_id):
            comment = self.comment_from_comment_id(comment_id)
            comment.delete()
            return self.redirect('/blog/%s' % post_id)
        else:
            return self.redirect('/blog/%s' % post_id + '?comment_error=True')

    def edit_comment(self, post_id):
        comment_id = self.request.POST.get('edit_comment')
        if self.validate_comment_author(comment_id):
            return self.redirect('/blog/edit_comment/%s' % comment_id)
        else:
            return self.redirect('/blog/%s' % post_id + '?comment_error=True')

    def like_post(self, post_id):
        post = self.post_from_post_id(post_id)
        if post.author != self.user.name:
            if self.user.name not in post.likes:
                post.likes.append(self.user.name)
                post.put()
                return self.redirect('/blog/%s' % post_id)
            else:
                return self.redirect('/blog/%s' % post_id +
                              '?like_error=True')
        else:
            return self.redirect('/login')

    def new_comment(self, post_id):
        content = self.request.POST.get('content')
        author = self.user.name
        c = Comment(post_id = post_id, author = author, content = content)
        c.put()
        return self.redirect('/blog/%s' % post_id)

    def list_likers(self):
        post_id = self.request.get('likers')
        return self.redirect('/blog/%s' % post_id + '?likers=' + post_id)

    def initialize(self, *a, **kw):
        """Stores the current user each time a request is made."""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid.split('|')[0]))


class MainPage(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie',
                                         'visits=%s' % new_cookie_val)

        if visits > 10000:
            self.write("You bin here more'n 10K goddamn times. Get a life!")
        elif visits == 1:
            self.write("This is your first visit!")
        else:
            self.write("You've been here %s times!" % visits)


class LoginHandler(Handler):
    def get(self):
        return self.render('login.html')

    def valid_login(self, username, password):
        user = User.by_name(username)
        if user:
            pw_hash = user.pw_hash
            if check_password(username, password, pw_hash):
                return 'Correct password'
            else:
                return 'Wrong password'
        else:
            return 'No such user'

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        login_status = self.valid_login(username, password)

        if login_status == 'Correct password':
            user = User.by_name(username)
            self.login(user)
            return self.redirect("/welcome")
        elif login_status == 'No such user':
            return self.render("login.html", username = username,
                        username_error = True)
        elif login_status == 'Wrong password':
            return self.render("login.html", username = username,
                        password_error = True)


class LogoutHandler(Handler):
    def get(self):
        """Nullifies user cookie upon log out."""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        return self.redirect("/login")


class SignUpHandler(Handler):
    def valid_signup(self, username, password, verify, email):
        signup_info = {'username': False, 'user_exists': False,
                       'password': False, 'verify': False, 'email': False}
        if not email or self.valid_email(email):
            signup_info['email'] = True
        if self.valid_username(username):
            signup_info['username'] = True
        if not User.all().filter('name =', username).get():
            signup_info['user_exists'] = True
        if self.valid_password(password):
            signup_info['password'] = True
        if self.password_match(password, verify):
            signup_info['verify'] = True
        return signup_info

    def get(self):
        return self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        signup_info = self.valid_signup(username, password, verify, email)

        if all(info is True for info in signup_info.values()):
            user = User.register(username, password, email = email)
            user.put()
            self.login(user)
            return self.redirect("/welcome")
        else:
            return self.render("signup.html", username = username, email = email,
                        username_error = not signup_info['username'],
                        user_exists = not signup_info['user_exists'],
                        password_error = not signup_info['password'],
                        verify_error = not signup_info['verify'],
                        email_error = not signup_info['email'])


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            return self.render("welcome.html", username = self.user.name)
        else:
            return self.redirect("/signup")


class MyPostsHandler(Handler):
    def get(self):
        if not self.user:
            return self.redirect('/login')

        if self.request.get('likers'):
            return self.list_likers()

        current_user = self.user.name
        posts = Post.user_posts(current_user)
        return self.render("myposts.html", posts = posts,
                           author = current_user)


class BlogHandler(Handler):
    def get(self):
        """Displays ten most recently created posts. If 'Likes: ' button is
        clicked, redirects to post's permalink page and displays list of users
        who have liked the given post."""
        if self.request.get('likers'):
            return self.list_likers()

        posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC LIMIT 10")
        return self.render("blog.html", posts = posts)

    def post(self):
        """Allows users to like other users' posts, but not their own, and not
        more than once per post."""
        if self.user:
            if self.request.POST.get('like'):
                post = self.post_from_post_id(self.request.POST.get('like'))
                if post.author == self.user.name:
                    return self.render("blog.html", like_own_error = True)
                elif self.user.name in post.likes:
                    return self.render("blog.html", like_twice_error = True)
                else:
                    post.likes.append(self.user.name)
                    post.put()
                    return self.render("blog.html")
        else:
            return self.redirect('/login')


class PostPageHandler(Handler):
    """Handler for the permalink page of each post. Displays 'Edit' and
    'Delete' buttons only if the current user is the post's author."""
    def get(self, post_id, likers_list = False, like_error = False,
            comment_error = False, author_buttons = False):
        post = self.post_from_post_id(post_id)
        if not post:
            self.error(404)
            return

        if self.request.get('likers'):
            likers_list = True

        if self.request.get('like_error'):
            like_error = True

        if self.request.get('comment_error'):
            comment_error = True

        comments = Comment.post_comments(post_id)

        if self.user:
            author_buttons = self.validate_author(post_id)

        return self.render("permalink.html", post = post, comments = comments,
                    author_buttons = author_buttons, likers_list = likers_list,
                    like_error = like_error, comment_error = comment_error)

    def post(self, post_id):
        """'post_id' parameter is passed in from the URL. The following if
        statements deal with the range of different POST requests available
        on the permalink page, which are complicated by the fact that some are
        restricted to the post's author, while others are restricted to users
        other than the post's author; the same applies for comments."""
        if not self.user:
            return self.redirect('/login')

        post = self.post_from_post_id(post_id)
        # Allows user to delete post, if they authored it.
        if self.request.POST.get('delete'):
            return self.delete_post(post_id)
        # Allows user to edit post if they authored it.
        elif self.request.POST.get('edit'):
            return self.edit_post(post_id)
        # Allows user to delete comment if they authored it.
        elif self.request.POST.get('delete_comment'):
            return self.delete_comment(post_id)
        # Allows user to edit comment if they authored it.
        elif self.request.POST.get('edit_comment'):
            return self.edit_comment(post_id)
        # Allows user to like post if they did not author it and have not
        # already liked it.
        elif self.request.POST.get('like'):
            return self.like_post(post_id)
        # Allows user to post a new comment.
        elif self.request.POST.get('content'):
            return self.new_comment(post_id)


class EditHandler(Handler):
    """Handler for page on which users can edit their own posts."""
    def get(self, post_id):
        if not self.validate_author(post_id):
            return self.redirect("/login")

        post = self.post_from_post_id(post_id)
        return self.render("edit.html", post = post)

    def post(self, post_id):
        if not self.validate_author(post_id):
            return self.redirect("/login")
        post = self.post_from_post_id(post_id)
        post.title = self.request.get("title")
        post.content = self.request.get("content")
        post.put()
        return self.redirect('/blog/myposts')


class CommentEditHandler(Handler):
    """Handler for page on which users can edit their own comments."""
    def get(self, comment_id):
        if not self.validate_comment_author(comment_id):
            return self.redirect("/login")

        comment = self.comment_from_comment_id(comment_id)
        return self.render("edit_comment.html", comment = comment)

    def post(self, comment_id):
        if not self.validate_comment_author(comment_id):
            return self.redirect("/login")
        comment = self.comment_from_comment_id(comment_id)
        comment.content = self.request.get("content")
        comment.put()
        return self.redirect('/blog/%s' % comment.post_id)


class NewPostHandler(Handler):
    def get(self):
        if self.user:
            return self.render("newpost.html")
        else:
            return self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')

        author = self.user.name
        title = self.request.get("title")
        content = self.request.get("content")

        if title and content:
            p = Post(title = title, content = content, author = author)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Title and content are required."
            return self.render("newpost.html", title=title, content=content,
                        error=error)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/?', BlogHandler),
    ('/blog/([0-9]+)', PostPageHandler),
    ('/blog/newpost', NewPostHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/blog/myposts', MyPostsHandler),
    ('/blog/edit/([0-9]+)', EditHandler),
    ('/blog/edit_comment/([0-9]+)', CommentEditHandler)
], debug=True)
