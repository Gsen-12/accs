class ClassViewSet(viewsets.ModelViewSet):
    queryset = Class.objects.all()
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return ClassCreateSerializer
        return ClassSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=False, methods=['get'])
    def my_classes(self, request):
        """获取当前教师创建的班级"""
        classes = Class.objects.filter(created_by=request.user)
        serializer = self.get_serializer(classes, many=True)
        return Response(serializer.data)


class ClassAssignmentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AssignStudentSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        classroom = serializer.validated_data['class_id']
        student_ids = serializer.validated_data['student_ids']

        # 验证教师权限
        if classroom.created_by != request.user:
            return Response({
                "code": 403,
                "message": "无权操作其他教师的班级"
            }, status=403)

        # 批量关联学生
        students = User.objects.filter(id__in=student_ids)
        classroom.students.add(*students)

        return Response({
            "code": 200,
            "message": f"成功添加{len(students)}名学生"
        })


class ClassViewSet(viewsets.ModelViewSet):
    # 继承ModelViewSet，自动实现CRUD接口（GET/POST/PUT/DELETE等）[5](@ref)
    queryset = Class.objects.all()  # 指定默认查询集为所有班级
    permission_classes = [IsAuthenticated]  # 仅允许认证用户访问

    def get_serializer_class(self):
        # 动态选择序列化器：创建班级时使用专用序列化器，其他操作使用默认[5,7](@ref)
        if self.action == 'create':
            return ClassCreateSerializer
        return ClassSerializer

    def perform_create(self, serializer):
        # 在创建班级时自动关联当前登录用户为创建者[3,6](@ref)
        serializer.save(created_by=self.request.user)

    @action(detail=False, methods=['get'])
    def my_classes(self, request):
        """自定义动作：获取当前教师创建的班级"""
        # 过滤查询集，仅返回当前用户创建的班级[5](@ref)
        classes = Class.objects.filter(created_by=request.user)
        serializer = self.get_serializer(classes, many=True)
        return Response(serializer.data)  # DRF的Response支持内容协商[6](@ref)