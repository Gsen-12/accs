from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Roles
from django.contrib.admin.models import LogEntry, ADDITION, CHANGE, DELETION
from django.contrib.contenttypes.models import ContentType
from .middleware import get_current_user


@receiver(post_save, sender=Roles)
def log_role_change(sender, instance, created,  ** kwargs):
    action_flag = ADDITION if created else CHANGE
    user = get_current_user()

    try:
        if not created:
            old = Roles.objects.get(pk=instance.pk)
            changes = instance.changes(old)
            change_message = "\n".join([f"{k}: {v[0]}→{v[1]}" for k, v in changes.items()])
        else:
            change_message = "新角色创建"

        LogEntry.objects.log_action(
            user_id=user.id if user else None,
            content_type_id=ContentType.objects.get_for_model(Roles).pk,
            object_id=instance.role_id,
            object_repr=str(instance),
            action_flag=action_flag,
            change_message=change_message
        )
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"角色日志记录失败: {str(e)}")


@receiver(post_delete, sender=Roles)
def log_role_delete(sender, instance,  ** kwargs):
    user = get_current_user()
    LogEntry.objects.log_action(
        user_id=user.id if user else None,
        content_type_id=ContentType.objects.get_for_model(Roles).pk,
        object_id=instance.role_id,
        object_repr=str(instance),
        action_flag=DELETION,
        change_message="角色删除"
    )
