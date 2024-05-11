import { useContext, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { AiOutlineDislike, AiOutlineLike } from "react-icons/ai";
import { AuthContext } from "../../providers/AuthProviders";
import { message } from "antd";
import ReactHtmlParser from 'react-html-parser';

const BlogDetails = () => {
  const { user } = useContext(AuthContext);
  const [blogs, setBlogs] = useState([]);
  const blogDescription = useParams();

  const fetchBlogData = () => {
    const url = `http://localhost:5000/newBlogs/${blogDescription?._id}`;
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        setBlogs(data);
        console.log(data);
      })
      .catch((error) => {
        console.log(error);
      });
  };

  useEffect(() => {
    fetchBlogData();
  }, [blogs]);

  const handleLike = async () => {
    const userEmail = user?.email;
    const reaction = "like";
    const response = await fetch(
      `http://localhost:5000/blog/update/likeDislike/${blogDescription._id}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ userEmail, reaction }),
      }
    );
    if (response) {
      const updatedBlog = await response.json();
      message.success("Blog Liked!");
      setBlogs(updatedBlog);
    } else {
      console.error("Failed to update like count");
    }
  };
  const handleDislike = async () => {
    const userEmail = user?.email;
    const reaction = "dislike";
    const response = await fetch(
      `http://localhost:5000/blog/update/likeDislike/${blogDescription._id}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ userEmail, reaction }),
      }
    );
    if (response) {
      const updatedBlog = await response.json();
      message.success("Blog Disliked!");
      setBlogs(updatedBlog);
    } else {
      console.error("Failed to update dislike count");
    }
  };
  return (
    <div className="flex justify-center items-center min-h-[60vh]">
      <div className="card w-4/5 bg-white border-2 rounded-xl border-black">
        <div className="card-body gap-10 text-wrap">
          <h2 className="text-5xl font-bold text-center">
            {blogs.blogTitle}
          </h2>
          <p style={{ overflowWrap: "break-word" }}>{ReactHtmlParser(blogs.blogBody)}</p>
          <div className="card-actions justify-end">
            <button
              className="btn btn-success btn-outline"
              onClick={handleLike}
            >
              <div className="flex items-center gap-2">
                <span className="text-xl">{blogs?.likes}</span>{" "}
                <AiOutlineLike size="2em" />
              </div>
            </button>
            <button
              className="btn btn-error btn-outline"
              onClick={handleDislike}
            >
              <div className="flex items-center gap-2">
                <span className="text-xl">{blogs?.dislikes}</span>{" "}
                <AiOutlineDislike size="2em" />
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BlogDetails;
