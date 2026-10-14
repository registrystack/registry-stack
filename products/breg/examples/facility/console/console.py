"""A small proving application. All Record and Action types are generated."""
from project import ProjectClient, RegisterFacilityInput, CorrectAddressInput

def facility_console(reader: ProjectClient, registrar: ProjectClient, author: ProjectClient,
                     facility_id: str, registration: RegisterFacilityInput,
                     correction: CorrectAddressInput) -> dict[str, object]:
    facility = reader.read('facility', facility_id)
    assignments = reader.related('facility', facility_id, 'assignments')
    first = assignments['items'][0] if assignments['items'] else None
    operator = reader.related('facility-assignment', first['id'], 'operator') if first else None
    registered = registrar.register_facility(registration, 'console-register-1')
    draft = author.correct_address(correction, 'console-correction-1')
    submitted = author.execute(author.prepare(draft, 'submit', {}, 'console-submit-1'))
    listing = author.list_proposals('correct-address')
    current = author.resume_proposal(listing['items'][0]) if listing['items'] else submitted
    return {'title': facility['title'], 'operator': operator, 'registered': registered, 'proposal': current}
