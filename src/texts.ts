import axios from 'axios';
const baseUrl = 'https://aqueous-plains-06397.herokuapp.com/api/texts';


export const getAll = () => {
    const request = axios.get(baseUrl)
    return request.then(response => response.data);
}