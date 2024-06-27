import whois
from datetime import datetime, timedelta

def fetch_whois_info(domain):
    w = whois.whois(domain)
    return w

def to_naive_utc(dt):
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt

def format_whois_info(w):
    now = datetime.utcnow()

    # Handle lists of dates and ensure they are naive UTC
    expiration_date = w.expiration_date
    if isinstance(expiration_date, list):
        expiration_date = min(expiration_date)
    if expiration_date:
        expiration_date = to_naive_utc(expiration_date)

    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = min(creation_date)
    if creation_date:
        creation_date = to_naive_utc(creation_date)

    updated_date = w.updated_date
    if isinstance(updated_date, list):
        updated_date = min(updated_date)
    if updated_date:
        updated_date = to_naive_utc(updated_date)

    expires_in = (expiration_date - now) if expiration_date else 'Unknown'
    
    if isinstance(expires_in, timedelta):
        days, seconds = expires_in.days, expires_in.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        expires_in_str = f"{hours} hours, {minutes} minutes and {seconds} seconds"
    else:
        expires_in_str = 'Unknown'

    formatted_info = f"""
    WHOIS information for {w.domain_name}
    Cache expires in {expires_in_str}
    
    Registrar Info
    Name: {w.registrar}
    Status: {'Active' if w.status else 'Inactive'}
    
    Important Dates
    Expires On: {expiration_date if expiration_date else 'Unknown'}
    Registered On: {creation_date if creation_date else 'Unknown'}
    Updated On: {updated_date if updated_date else 'Unknown'}
    
    Similar Domains
    {' | '.join(w.domain_name) if isinstance(w.domain_name, list) else w.domain_name}
    
    Registrar Data
    domain:                        {w.domain_name}
    status:                        {w.status if w.status else 'Unknown'}
    hold:                          {'NO' if w.status == 'active' else 'YES'}
    registrar:                     {w.registrar}
    Expiry Date:                   {expiration_date if expiration_date else 'Unknown'}
    created:                       {creation_date if creation_date else 'Unknown'}
    last-update:                   {updated_date if updated_date else 'Unknown'}
    source:                        WHOIS
    nserver:                       {' | '.join(w.name_servers) if w.name_servers else 'Unknown'}
    source:                        WHOIS
    registrar:                     {w.registrar}
    address:                       {w.registrar_address if w.registrar_address else 'Unknown'}
    country:                       {w.registrar_country if w.registrar_country else 'Unknown'}
    phone:                         {w.registrar_phone if w.registrar_phone else 'Unknown'}
    e-mail:                        {w.registrar_email if w.registrar_email else 'Unknown'}
    website:                       {w.registrar_url if w.registrar_url else 'Unknown'}
    
    >>> Last update of WHOIS database: {now.strftime('%Y-%m-%dT%H:%M:%SZ')} <<<
    """
    
    return formatted_info
