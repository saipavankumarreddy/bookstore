# # if request.form['uname'] != 'admin' and request.form['psw'] != 'admin':
#         #     flash('Invalid username or password. Please try again.')
#         #     return redirect(url_for('homepage'))
#     uname = request.form['uname']
#     pwd = request.form['psw']
#     hash_pwd = User(uname, pwd)
#     if UserDetails.query(UserDetails.email_ID == uname).get():
#         user_entity = UserDetails.query(UserDetails.email_ID == uname).get():
#         if user_entity.password == hash_pwd:
#             session['logged_in'] = True
#             return redirect(url_for('userpage'))
#         else:
#             flash('Invalid username or password. Please try again.')
#             return redirect(url_for('userpage'))
#
#     # for user in userdet:
#     #     if user.email_ID == uname and user.password == hash_pwd.set_password(pwd):
#     #         session['logged_in'] = True
#     #         return redirect(url_for('userpage'))
#     #     else:
#     #         continue
#     else:
#         flash('Invalid credentials.')
#         return redirect(url_for('homepage'))
#     # return 'logged in'

name = 'Surya'
my_name = str(name)
print my_name