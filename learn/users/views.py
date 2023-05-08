from django.shortcuts import render

# Create your views here.

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
from .serializers import UserSerializer
from .models import User
from django.http import Http404
import jwt
import datetime


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found')

        if not user.check_password(password):
            return AuthenticationFailed('Incorrect password')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'lat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret',
                           algorithm='HS256').decode('utf-8')

        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {'jwt': token}

        return response


class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unathenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS2'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unathenticated!')

        user = User.objects.filter(id=payload[id]).first()
        serializer = UserSerializer(user)

        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Success'
        }
        return response

class PorductViewList(APIView):

    def token_authentication(self, token):

        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS2'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            return User.objects.filter(id=payload[id]).first()
        except User.DoesNotExist:
            return Http404

    def get(self, request, format=None):
        products = Product.objects.all()
        serializer = ProductAllSerializer(products, many=True)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        user_dic = {'user':user.username}
        serializer = ProductListSerializer(data=request.data, context = user_dic)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductViewDetails(APIView):

    def get_object(self, pk):
        try:
            return User.objects.get(username=pk)
        except User.DoesNotExist:
            return Http404

    def get_product_object(self, user):
        try:
            return PlanChoices.objects.get(user=user)
        except PlanChoices.DoesNotExist:
            raise Http404

    def token_authentication(self, token):

        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS2'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            return User.objects.filter(id=payload[id]).first()
        except User.DoesNotExist:
            return Http404

    def get(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductAllSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductPatchSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductPatchSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductPatchSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CartView(APIView):
    def token_authentication(self, token):

        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS2'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            return User.objects.filter(id=payload[id]).first()
        except User.DoesNotExist:
            return Http404

    def post(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        user_dic = {'user':user.username}
        serializer = ProductListSerializer(data=request.data, context = user_dic)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        user_dic = {'user': user.username}
        serializer = ProductListSerializer(data=request.data, context=user_dic)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        user_dic = {'user': user.username}
        serializer = ProductListSerializer(data=request.data, context=user_dic)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        user_dic = {'user': user.username}
        serializer = ProductListSerializer(data=request.data, context=user_dic)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        user_dic = {'user': user.username}
        serializer = ProductListSerializer(data=request.data, context=user_dic)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderView(APIView):
    def token_authentication(self, token):

        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS2'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            return User.objects.filter(id=payload[id]).first()
        except User.DoesNotExist:
            return Http404



    def post(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductPatchSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk, *args, **kwargs):
        products = Product.objects.all()
        serializer = ProductAllSerializer(products, many=True)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def patch(self, request, pk, *args, **kwargs):
    #     pass

    def put(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductPatchSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        user = self.token_authentication(token)
        product = self.get_product_object(pk)
        context = {'user': user, 'product': product}
        serializer = ProductPatchSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)