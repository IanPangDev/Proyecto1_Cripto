let friends;

chat = {
  container: document.querySelector('.container .right'),
  current: null,
  person: null,
  name: document.querySelector('.container .right .top .name') };

function setActiveChat(f) {
  const activeFriend = friends.list.querySelector('.active');

  if (activeFriend) {
      activeFriend.classList.remove('active');
  }

  f.classList.add('active');

  chat.current = chat.container.querySelector('.active-chat');
  chat.person = f.getAttribute('data-chat');

  if (chat.current) {
      chat.current.classList.remove('active-chat');
  }

  const newChat = chat.container.querySelector(`[data-chat="${chat.person}"]`);
  if (newChat) {
      newChat.classList.add('active-chat');
      
      // Añadir el atributo 'To' cuando el chat está activo
      const name = f.querySelector('.name').innerText;
      chat.name.innerHTML = `To: <span class="name">${name}</span>`;
  } else {
      chat.name.innerHTML = ''; // Limpiar si no hay chat
  }

  friends.name = f.querySelector('.name').innerText;
}

function setupChatListeners() {
  friends = {
    list: document.querySelector('ul.people'),
    all: document.querySelectorAll('.left .person'),
    name: ''
  };
  const persons = document.querySelectorAll('.person');

  persons.forEach(person => {
      person.addEventListener('click', function() {
          setActiveChat(this);
      });
  });
}