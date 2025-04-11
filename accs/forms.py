# from django import forms
# from captcha.fields import CaptchaField
#
# class CaptchaLoginForm(forms.Form):
#     username = forms.CharField(label="用户名", max_length=128)
#     password = forms.CharField(
#         label="密码",
#         max_length=256,
#         widget=forms.PasswordInput(attrs={'class': 'form-control'})
#     )
#     captcha = CaptchaField(
#         label='验证码',
#         error_messages={'invalid': '验证码错误'},
#         # 设置验证码输入框和图片的HTML属性
#         widget=forms.TextInput(attrs={'placeholder': '输入验证码'})
#     )