import whois
from datetime import datetime, timezone, timedelta

def fetch_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return {'error': str(e)}

def to_naive_utc(dt):
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

def format_whois_info(w):
    if 'error' in w:
        return w['error']

    now = datetime.utcnow()

    # Handle lists of dates and ensure they are naive UTC
    def convert_to_naive_utc(dates):
        if isinstance(dates, list):
            dates = [to_naive_utc(date) for date in dates]
            return min(dates)
        return to_naive_utc(dates)

    expiration_date = convert_to_naive_utc(w.expiration_date)
    creation_date = convert_to_naive_utc(w.creation_date)
    updated_date = convert_to_naive_utc(w.updated_date)

    expires_in = (expiration_date - now) if expiration_date else 'Unknown'
    
    if isinstance(expires_in, timedelta):
        days, seconds = expires_in.days, expires_in.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        expires_in_str = f"{hours} hours, {minutes} minutes and {seconds} seconds"
    else:
        expires_in_str = 'Unknown'

    # Ensure all fields are checked for None or null values
    domain_name = ' | '.join(w.domain_name) if isinstance(w.domain_name, list) else (w.domain_name or 'Unknown')
    registrar = w.registrar or 'Unknown'
    status = ' | '.join(w.status) if isinstance(w.status, list) else (w.status or 'Unknown')
    name_servers = ' | '.join(w.name_servers) if w.name_servers else 'Unknown'
    registrar_address = getattr(w, 'registrar_address', 'Unknown')
    registrar_country = getattr(w, 'registrar_country', 'Unknown')
    registrar_phone = getattr(w, 'registrar_phone', 'Unknown')
    registrar_email = getattr(w, 'registrar_email', 'Unknown')
    registrar_url = getattr(w, 'registrar_url', 'Unknown')

    # Ensure other WHOIS fields are not null
    name = w.name or 'Unknown'
    org = w.org or 'Unknown'
    address = w.address or 'Unknown'
    city = w.city or 'Unknown'
    state = w.state or 'Unknown'
    postal_code = getattr(w, 'registrant_postal_code', 'Unknown')
    country = w.country or 'Unknown'

    formatted_info = f"""
    WHOIS information for {domain_name}
    Cache expires in {expires_in_str}
    
    Registrar Info
    Name: {registrar}
    Status: {status}
    
    Important Dates
    Expires On: {expiration_date if expiration_date else 'Unknown'}
    Registered On: {creation_date if creation_date else 'Unknown'}
    Updated On: {updated_date if updated_date else 'Unknown'}
    
    Similar Domains
    {domain_name}
    
    Registrar Data
    domain:                        {domain_name}
    status:                        {status}
    hold:                          {'NO' if 'active' in status.lower() else 'YES'}
    registrar:                     {registrar}
    Expiry Date:                   {expiration_date if expiration_date else 'Unknown'}
    created:                       {creation_date if creation_date else 'Unknown'}
    last-update:                   {updated_date if updated_date else 'Unknown'}
    source:                        WHOIS
    nserver:                       {name_servers}
    source:                        WHOIS
    registrar:                     {registrar}
    address:                       {registrar_address}
    country:                       {registrar_country}
    phone:                         {registrar_phone}
    e-mail:                        {registrar_email}
    website:                       {registrar_url}

    Registrant Info
    Name: {name}
    Organization: {org}
    Address: {address}
    City: {city}
    State: {state}
    Postal Code: {postal_code}
    Country: {country}
    
    >>> Last update of WHOIS database: {now.strftime('%Y-%m-%dT%H:%M:%SZ')} <<<
    """
    
    return formatted_info
