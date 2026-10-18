# Imported by "<project>/<group>/<principal>". The project is required.
# Project and group names cannot contain "/", so the ID is split at the first two "/" and the principal
# is the rest, which may itself contain "/".
terraform import permio_group_member.alice default/oncall/user_alice
terraform import permio_group_member.bob default/oncall/user/bob@example.com
