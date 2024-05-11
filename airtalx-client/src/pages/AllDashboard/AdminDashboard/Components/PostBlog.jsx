import { message } from "antd";
import JoditEditor from 'jodit-react';
import { useContext, useEffect, useRef, useState } from "react";
import { AuthContext } from "../../../../providers/AuthProviders";

const PostBlog = () => {
    const { user } = useContext(AuthContext);
    const [content1, setContent1] = useState('');
    const [defaultDate, setDefaultDate] = useState('');
    const editor1 = useRef(null);

    useEffect(() => {
        const currentDate = new Date();
        const formattedDate = currentDate.toLocaleDateString('en-US', {
            day: '2-digit',
            month: 'short',
            year: 'numeric'
        });
        setDefaultDate(formattedDate);
    }, [])


    const postABlog = (e) => {
        e.preventDefault();
        const form = e.target;
        const blogTitle = form.blogTitle.value;
        const blogPostDate = form.blogPostDate.value;
        const blogPostedByName = form.blogPostedByName.value;
        const blogPostedByEmail = form.blogPostedByEmail.value;
        const blogBody = content1;
        const likes = 0;
        const dislikes = 0;
        const reactLike = [];
        const reactDisLike = [];

        const blogPost = { blogTitle, blogPostDate, blogPostedByName, blogPostedByEmail, blogBody, likes, dislikes, reactLike, reactDisLike }
        fetch('http://localhost:5000/newBlogs', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(blogPost)
        })
            .then(res => res.json())
            .then(data => {
                if (data.insertedId) {
                    message.success("Blog Posted Sucessfully!");
                    console.log(data)
                    form.reset();
                }
                else {
                    message.error("Blog did not Posted!")
                }
            })
            .catch(error => {
                console.error('Error storing user data:', error);
            });
    }
    return (
        <div className="m-6 custom-shadow">
            <form onSubmit={postABlog} action="" className="p-6">
                <div className="py-2">
                    <h4 className="text-2xl font-semibold">Blog Headline</h4>
                    <div>
                        <input name='blogTitle' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder='Blog Headline' type="text" />
                    </div>
                </div>
                <div className="py-2 hidden">
                    <h4 className="text-2xl font-semibold">Blog Post Date</h4>
                    <div>
                        <input name='blogPostDate' value={defaultDate} className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder='Blog Headline' type="text" />
                    </div>
                </div>
                <div className="py-2 hidden">
                    <h4 className="text-2xl font-semibold">Blog Headline</h4>
                    <div>
                        <input name='blogPostedByName' value={user?.name} className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder='Blog Headline' type="text" />
                    </div>
                </div>
                <div className="py-2 hidden">
                    <h4 className="text-2xl font-semibold">Blog Headline</h4>
                    <div>
                        <input name='blogPostedByEmail' value={user?.email} className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder='Blog Headline' type="text" />
                    </div>
                </div>
                <div className="pt-8">
                    <h4 className="text-2xl font-semibold">Blog Body</h4>
                    {/* <p>Write a detailed job description. Include all the essential information</p> */}
                    <div>
                        {/* <textarea name='blogBody' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" id="" cols="30" rows="10"></textarea> */}
                        <div className="custom-class no-tailwind custom-ul custom-ol">
                            <JoditEditor ref={editor1} value={content1} onChange={newContent => setContent1(newContent)} />
                        </div>
                    </div>
                </div>
                <div>
                    <button className="bg-[#1d9cb5] text-white text-xl mt-2 rounded px-4 py-2">Post Blog</button>
                </div>
            </form>
        </div>
    );
};

export default PostBlog;