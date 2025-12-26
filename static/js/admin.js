// Admin Dashboard JavaScript
let selectedTicketId = null;

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
    
    if (view === 'received') {
        loadReceivedTickets();
    } else if (view === 'resolved') {
        loadResolvedTickets();
    }
}

// Load tickets
async function loadReceivedTickets() {
    try {
        const response = await fetch('/api/received-tickets');
        const tickets = await response.json();
        displayTickets(tickets, 'received-tickets', 'received');
    } catch (error) {
        console.error('Error loading received tickets:', error);
    }
}

async function loadResolvedTickets() {
    try {
        const response = await fetch('/api/resolved-tickets');
        const tickets = await response.json();
        displayTickets(tickets, 'resolved-tickets', 'resolved');
    } catch (error) {
        console.error('Error loading resolved tickets:', error);
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
                <div class="ticket-id">Ticket #${ticket.id} - ${ticket.client}</div>
                <span class="ticket-status ${ticket.status === 'pending' ? 'status-pending' : 'status-resolved'}">
                    ${ticket.status === 'pending' ? 'Pending' : 'Resolved'}
                </span>
            </div>
            <div class="ticket-problem">${ticket.problem.substring(0, 100)}...</div>
            <div class="ticket-client">Client: ${ticket.client}</div>
            <div class="ticket-date">Created: ${new Date(ticket.created_at).toLocaleDateString()}</div>
            ${type === 'received' ? `
            <div class="ticket-actions">
                <button class="btn-solution" onclick="openSolutionModal(event, ${ticket.id})">Write Solution</button>
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
                    <div class="detail-label">Client:</div>
                    <div class="detail-value">${ticket.client}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Status:</div>
                    <div class="detail-value">
                        <span class="ticket-status ${ticket.status === 'pending' ? 'status-pending' : 'status-resolved'}">
                            ${ticket.status === 'pending' ? 'Pending' : 'Resolved'}
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

// Open solution modal
function openSolutionModal(event, ticketId) {
    event.stopPropagation();
    selectedTicketId = ticketId;
    document.getElementById('solutionModal').classList.add('show');
}

// Modal close
document.querySelectorAll('.close').forEach(closeBtn => {
    closeBtn.addEventListener('click', function() {
        this.closest('.modal').classList.remove('show');
    });
});

// Submit solution form
document.getElementById('solutionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const solution = document.getElementById('solutionText').value;
    
    try {
        const response = await fetch(`/api/tickets/${selectedTicketId}/solution`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ solution })
        });
        
        if (response.ok) {
            const message = document.getElementById('solution-message');
            message.textContent = 'Solution sent successfully!';
            message.classList.remove('error');
            message.classList.add('success');
            message.style.display = 'block';
            
            document.getElementById('solutionForm').reset();
            
            setTimeout(() => {
                document.getElementById('solutionModal').classList.remove('show');
                message.style.display = 'none';
                loadReceivedTickets();
            }, 1500);
        }
    } catch (error) {
        console.error('Error submitting solution:', error);
        const message = document.getElementById('solution-message');
        message.textContent = 'Error submitting solution!';
        message.classList.remove('success');
        message.classList.add('error');
        message.style.display = 'block';
    }
});

// Initial load
loadReceivedTickets();
