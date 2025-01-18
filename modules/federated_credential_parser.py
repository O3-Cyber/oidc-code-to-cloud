from typing import Optional
from helpers.data_models import SubjectIdentifier


def parse_subject_identifier(subject: str) -> Optional[SubjectIdentifier]:
    """
    Parse the subject identifier from the subject string.

    Args:
        subject (str): The subject string to parse.

    Returns:
        Optional[SubjectIdentifier]: The parsed subject identifier or None if parsing fails.

    Example:
        >>> subject = "repo:karimelmel/cloud-infra-as-code:pull_request"
        >>> parse_subject_identifier(subject)
        SubjectIdentifier(
            organization='karimelmel',
            repository='cloud-infra-as-code',
            entity_type='pull_request',
        )
    """
    parts = subject.split(":")
    if len(parts) >= 3 and parts[0] == "repo":
        org_repo = parts[1].split("/")
        if len(org_repo) != 2:
            return None

        organization, repository = org_repo
        entity_type = parts[2]
        entity_name = ":".join(parts[3:]) if len(parts) > 3 else ""

        # Handle special case for pull_request
        if entity_type == "pull_request":
            return SubjectIdentifier(
                organization=organization,
                repository=repository,
                entity_type="pull_request",
                entity_name="*",
            )

        # Handle refs case
        if entity_type == "ref" and entity_name.startswith("refs/"):
            entity_type = "branch"
            entity_name = entity_name.replace("refs/heads/", "")

        return SubjectIdentifier(
            organization=organization,
            repository=repository,
            entity_type=entity_type,
            entity_name=entity_name,
        )
    return None
