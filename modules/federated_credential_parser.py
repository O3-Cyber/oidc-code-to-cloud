from typing import Dict, List, Optional
from helpers.data_models import SubjectIdentifier

def parse_subject_identifier(subject: str) -> Optional[SubjectIdentifier]:
    """
    Parse the subject identifier from the subject string.

    Args:
        subject (str): The subject string to parse.

    Returns:
        Optional[SubjectIdentifier]: The parsed subject identifier or None if parsing fails.
    
    Example:
        >>> subject = "repo:my-org:my-repo:branch:main"
        >>> parse_subject_identifier(subject)
        SubjectIdentifier(
            organization='my-org',
            repository='my-repo',
            entity_type='branch',
            entity_name='main'
        )
    """
    parts = subject.split(':')
    if len(parts) >= 5 and parts[0] == "repo":
        # Extract entity type and entity name from the parts
        entity_type, entity_name = parts[3].split('/', 1) if '/' in parts[3] else (parts[3], parts[4])
        return SubjectIdentifier(
            organization=parts[1],
            repository=parts[2],
            entity_type=entity_type,
            entity_name=entity_name
        )
    return None