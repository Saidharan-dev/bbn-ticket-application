// Client Dashboard JavaScript
let selectedTicketId = null;
let allPendingTickets = [];

// Menu navigation
document.querySelectorAll('.menu-item').forEach(item => {
    item.addEventListener('click', function() {
        const view = this.getAttribute('data-view');
        switchView(view);
        
        document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
        this.classList.add('active');
    });
});

function switchView(view) {
    document.querySelectorAll('.view-section').forEach(section => {
        section.classList.remove('active');
    });
    
    const viewElement = document.getElementById(view + '-view');
    if (viewElement) {
        viewElement.classList.add('active');
    }
    
    if (view === 'pending') {
        loadPendingTickets();
    } else if (view === 'previous') {
        loadPreviousTickets();
    }
}

// Load tickets
async function loadPendingTickets() {
    try {
        const response = await fetch('/api/tickets');
        const tickets = await response.json();
        
        const pendingTickets = tickets.filter(t => t.status === 'pending');
        allPendingTickets = pendingTickets;
        populateClientFilters();
        displayFilteredPending();
    } catch (error) {
        console.error('Error loading pending tickets:', error);
    }
}

function populateClientFilters() {
    const userSelect = document.getElementById('filterRaisedBy');
    const desigSelect = document.getElementById('filterDesignation');
    if (!userSelect || !desigSelect) return;

    const users = Array.from(new Set(allPendingTickets.map(t => t.raised_by).filter(Boolean)));
    const desigs = Array.from(new Set(allPendingTickets.map(t => t.designation).filter(Boolean)));

    // populate users
    userSelect.innerHTML = '<option value="">All Users</option>' + users.map(u => `<option value="${u}">${u}</option>`).join('');
    desigSelect.innerHTML = '<option value="">All Designations</option>' + desigs.map(d => `<option value="${d}">${d}</option>`).join('');

    userSelect.addEventListener('change', displayFilteredPending);
    desigSelect.addEventListener('change', displayFilteredPending);
}

function displayFilteredPending() {
    const user = document.getElementById('filterRaisedBy')?.value || '';
    const desig = document.getElementById('filterDesignation')?.value || '';

    let filtered = allPendingTickets.slice();
    if (user) filtered = filtered.filter(t => (t.raised_by || '') === user);
    if (desig) filtered = filtered.filter(t => (t.designation || '') === desig);

    displayTickets(filtered, 'pending-tickets', 'pending');
}

async function loadPreviousTickets() {
    try {
        const response = await fetch('/api/tickets');
        const tickets = await response.json();
        
        const resolvedTickets = tickets.filter(t => t.status === 'resolved');
        displayTickets(resolvedTickets, 'previous-tickets', 'resolved');
    } catch (error) {
        console.error('Error loading previous tickets:', error);
    }
}

function displayTickets(tickets, containerId, type) {
    const container = document.getElementById(containerId);
    
    if (tickets.length === 0) {
        container.innerHTML = '<p class="loading">No tickets found.</p>';
        return;
    }
    
    container.innerHTML = tickets.map(ticket => `
        <div class="ticket-card" onclick="viewTicket(${ticket.id})">
            <div class="ticket-header">
                <div style="display:flex; flex-direction:column;">
                    <div class="ticket-id">Ticket #${ticket.id}</div>
                    <div class="ticket-raised">Raised by: ${ticket.raised_by || '—'} (${ticket.designation || '—'})</div>
                </div>
                <div class="ticket-right">
                    <div class="ticket-priority">Priority: ${ticket.priority || 'Medium'}</div>
                    <span class="ticket-status ${ticket.status === 'pending' ? 'status-pending' : 'status-resolved'}">
                        ${ticket.status === 'pending' ? 'Not Resolved' : 'Resolved'}
                    </span>
                </div>
            </div>
            <div class="ticket-problem">${ticket.problem.substring(0, 100)}...</div>
            <div class="ticket-date">Created: ${new Date(ticket.created_at).toLocaleDateString()}</div>
            ${ticket.status === 'resolved' && ticket.solution ? `
                <div style="margin-top: 10px; color: #27ae60;">
                    ✓ Solution Available
                </div>
            ` : ''}
        </div>
    `).join('');
}

// View ticket details
function viewTicket(ticketId) {
    selectedTicketId = ticketId;
    
    fetch(`/api/tickets/${ticketId}`)
        .then(response => response.json())
        .then(ticket => {
            let detailsHTML = `
                <div class="detail-row">
                    <div class="detail-label">Ticket ID:</div>
                    <div class="detail-value">#${ticket.id}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Priority:</div>
                    <div class="detail-value">${ticket.priority || 'Medium'}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Raised By:</div>
                    <div class="detail-value">${ticket.raised_by || '—'}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Designation:</div>
                    <div class="detail-value">${ticket.designation || '—'}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Status:</div>
                    <div class="detail-value">
                        <span class="ticket-status ${ticket.status === 'pending' ? 'status-pending' : 'status-resolved'}">
                            ${ticket.status === 'pending' ? 'Not Resolved' : 'Resolved'}
                        </span>
                    </div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Problem:</div>
                    <div class="detail-value">${ticket.problem}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Created:</div>
                    <div class="detail-value">${new Date(ticket.created_at).toLocaleString()}</div>
                </div>
                ${ticket.attachments && ticket.attachments.length > 0 ? `
                <div class="detail-row">
                    <div class="detail-label">Attachments:</div>
                    <div class="detail-value">${ticket.attachments.join(', ')}</div>
                </div>
                ` : ''}
                ${ticket.solution ? `
                <div class="detail-row">
                    <div class="detail-label">Solution:</div>
                    <div class="detail-value">
                        <div class="solution-box">${ticket.solution}</div>
                        <div style="font-size: 12px; color: #999;">
                            Resolved: ${new Date(ticket.solution_date).toLocaleString()}
                        </div>
                    </div>
                </div>
                ` : ''}
            `;
            
            document.getElementById('ticketDetails').innerHTML = detailsHTML;
            document.getElementById('ticketModal').classList.add('show');
        })
        .catch(error => console.error('Error loading ticket:', error));
}

// Modal close
document.querySelector('.close').addEventListener('click', function() {
    document.getElementById('ticketModal').classList.remove('show');
});

// Submit ticket form
document.getElementById('ticketForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const problem = document.getElementById('problem').value;
    const raised_by = document.getElementById('raised_by') ? document.getElementById('raised_by').value.trim() : '';
    const designation = document.getElementById('designation') ? document.getElementById('designation').value.trim() : '';
    const priority = document.getElementById('priority') ? document.getElementById('priority').value : 'Medium';
    const fileInput = document.getElementById('files');
    const attachments = Array.from(fileInput.files).map(f => f.name);
    
    try {
        const response = await fetch('/api/tickets', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                problem,
                raised_by,
                designation,
                priority,
                attachments
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            
            const message = document.getElementById('form-message');
            message.textContent = 'Ticket submitted successfully!';
            message.classList.add('success');
            message.style.display = 'block';
            
            document.getElementById('ticketForm').reset();
            
            setTimeout(() => {
                message.style.display = 'none';
            }, 3000);
            
            setTimeout(() => {
                loadPendingTickets();
            }, 1000);
        }
    } catch (error) {
        console.error('Error submitting ticket:', error);
        const message = document.getElementById('form-message');
        message.textContent = 'Error submitting ticket!';
        message.classList.add('error');
        message.style.display = 'block';
    }
});

// Initial load
loadPendingTickets();
